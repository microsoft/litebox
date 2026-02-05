// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common elements to enable OP-TEE-like functionalities

#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use litebox::platform::RawConstPointer as _;
use litebox::utils::TruncateExt;
use litebox_common_linux::{PtRegs, errno::Errno};
use modular_bitfield::prelude::*;
use modular_bitfield::specifiers::{B8, B54};
use num_enum::TryFromPrimitive;
use syscall_nr::{LdelfSyscallNr, TeeSyscallNr};
use zerocopy::{FromBytes, Immutable, IntoBytes};

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
    GetProperty {
        prop_set: TeePropSet,
        index: u32,
        name: Platform::RawMutPointer<u8>,
        name_len: Platform::RawMutPointer<u32>,
        buf: Platform::RawMutPointer<u8>,
        blen: Platform::RawMutPointer<u32>,
        prop_type: Platform::RawMutPointer<u32>,
    },
    GetPropertyNameToIndex {
        prop_set: TeePropSet,
        name: Platform::RawConstPointer<u8>,
        name_len: usize,
        index: Platform::RawMutPointer<u32>,
    },
    OpenTaSession {
        ta_uuid: Platform::RawConstPointer<TeeUuid>,
        cancel_req_to: u32,
        usr_params: Platform::RawConstPointer<UteeParams>,
        ta_sess_id: Platform::RawMutPointer<u32>,
        ret_orig: Platform::RawMutPointer<TeeOrigin>,
    },
    CloseTaSession {
        ta_sess_id: u32,
    },
    InvokeTaCommand {
        ta_sess_id: u32,
        cancel_req_to: u32,
        cmd_id: u32,
        params: Platform::RawConstPointer<UteeParams>,
        ret_orig: Platform::RawMutPointer<TeeOrigin>,
    },
    CheckAccessRights {
        flags: TeeMemoryAccessRights,
        buf: Platform::RawConstPointer<u8>,
        len: usize,
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
    CipherFinal {
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
        max_size: u32,
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
        attrs: Platform::RawConstPointer<UteeAttribute>,
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
    pub fn try_from_raw(syscall_number: usize, ctx: &PtRegs) -> Result<Self, Errno> {
        let ctx = SyscallContext::from_pt_regs(ctx);
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
            TeeSyscallNr::GetProperty => SyscallRequest::GetProperty {
                prop_set: TeePropSet::try_from_usize(ctx.syscall_arg(0))?,
                index: u32::try_from(ctx.syscall_arg(1)).map_err(|_| Errno::EINVAL)?,
                name: Platform::RawMutPointer::from_usize(ctx.syscall_arg(2)),
                name_len: Platform::RawMutPointer::from_usize(ctx.syscall_arg(3)),
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(4)),
                blen: Platform::RawMutPointer::from_usize(ctx.syscall_arg(5)),
                prop_type: Platform::RawMutPointer::from_usize(ctx.syscall_arg(6)),
            },
            TeeSyscallNr::GetPropertyNameToIndex => SyscallRequest::GetPropertyNameToIndex {
                prop_set: TeePropSet::try_from_usize(ctx.syscall_arg(0))?,
                name: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                name_len: ctx.syscall_arg(2),
                index: Platform::RawMutPointer::from_usize(ctx.syscall_arg(3)),
            },
            TeeSyscallNr::OpenTaSession => SyscallRequest::OpenTaSession {
                ta_uuid: Platform::RawConstPointer::from_usize(ctx.syscall_arg(0)),
                cancel_req_to: u32::try_from(ctx.syscall_arg(1)).map_err(|_| Errno::EINVAL)?,
                usr_params: Platform::RawConstPointer::from_usize(ctx.syscall_arg(2)),
                ta_sess_id: Platform::RawMutPointer::from_usize(ctx.syscall_arg(3)),
                ret_orig: Platform::RawMutPointer::from_usize(ctx.syscall_arg(4)),
            },
            TeeSyscallNr::CloseTaSession => SyscallRequest::CloseTaSession {
                ta_sess_id: u32::try_from(ctx.syscall_arg(0)).map_err(|_| Errno::EINVAL)?,
            },
            TeeSyscallNr::InvokeTaCommand => SyscallRequest::InvokeTaCommand {
                ta_sess_id: u32::try_from(ctx.syscall_arg(0)).map_err(|_| Errno::EINVAL)?,
                cancel_req_to: u32::try_from(ctx.syscall_arg(1)).map_err(|_| Errno::EINVAL)?,
                cmd_id: u32::try_from(ctx.syscall_arg(2)).map_err(|_| Errno::EINVAL)?,
                params: Platform::RawConstPointer::from_usize(ctx.syscall_arg(3)),
                ret_orig: Platform::RawMutPointer::from_usize(ctx.syscall_arg(4)),
            },
            TeeSyscallNr::CheckAccessRights => SyscallRequest::CheckAccessRights {
                flags: TeeMemoryAccessRights::try_from_usize(ctx.syscall_arg(0))?,
                buf: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
                len: ctx.syscall_arg(2),
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
            TeeSyscallNr::CipherFinal => SyscallRequest::CipherFinal {
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
                max_size: u32::try_from(ctx.syscall_arg(1)).map_err(|_| Errno::EINVAL)?,
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
                attrs: Platform::RawConstPointer::from_usize(ctx.syscall_arg(1)),
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

/// Helper macro to define open enumerations, which it expands to structs with
/// constants, such that the type supports exhaustive storage of all values of
/// the underlying type.
///
/// E.g., the following enum expands to a value that stores any possible `u32`.
///
/// ```ignore
/// open_enum! {
///   /// Some documentation
///   enum ExampleEnum: u32 {
///     VariantOne = 1,
///     VariantTwo = 2,
///   }
/// }
/// ```
// FUTURE(jayb): consider moving this to `litebox` or a helper crate
macro_rules! open_enum {
    ($(#[$meta:meta])* $pub:vis enum $name:ident : $ty:ty { $(
        $variant:ident = $value:literal,
    )+ }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes)]
        #[repr(transparent)]
        $pub struct $name($ty);
        #[allow(non_upper_case_globals)]
        impl $name {
            $($pub const $variant: $name = $name($value);)*
            $pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
                Ok(match <$ty>::try_from(value).map_err(|_| Errno::EINVAL)? {
                    $($value => Self::$variant,)*
                    _ => return Err(Errno::EINVAL),
                })
            }
            /// Get the underlying value for `self`.
            $pub fn value(&self) -> &$ty {
                &self.0
            }
        }
    };
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
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, FromBytes, IntoBytes)]
#[repr(C)]
pub struct TeeObjHandle(pub u32);

impl TeeObjHandle {
    pub const NULL: Self = TeeObjHandle(0);

    pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
        u32::try_from(value)
            .map_err(|_| Errno::EINVAL)
            .map(TeeObjHandle)
    }
}

/// A handle for `TeeCrypState`. Like `TeeObjHandle`, this is a handle for
/// the cryptographic state (e.g., created through `CrypStateAlloc`) to be provided to
/// a TA in the user space.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, FromBytes, IntoBytes)]
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
/// type (4 bits) and two 8-byte data (values or addresses).
#[derive(Clone, Copy, Default, FromBytes, Immutable, IntoBytes)]
#[repr(C)]
pub struct UteeParams {
    pub types: UteeParamsTypes,
    pub vals: [u64; TEE_NUM_PARAMS * 2],
}
const TEE_NUM_PARAMS: usize = 4;

#[expect(
    clippy::identity_op,
    reason = "the macro auto-generates this, but some issue causes it to still bubble up; this suppresses it the hard way"
)]
mod workaround_identity_op_suppression {
    use modular_bitfield::prelude::*;
    use modular_bitfield::specifiers::{B4, B48};
    use zerocopy::{FromBytes, Immutable, IntoBytes};
    #[bitfield]
    #[derive(Clone, Copy, Default, FromBytes, Immutable, IntoBytes)]
    #[repr(C)]
    pub struct UteeParamsTypes {
        pub type_0: B4,
        pub type_1: B4,
        pub type_2: B4,
        pub type_3: B4,
        #[skip]
        __: B48,
    }
}
pub use workaround_identity_op_suppression::UteeParamsTypes;

const TEE_PARAM_TYPE_NONE: u8 = 0;
const TEE_PARAM_TYPE_VALUE_INPUT: u8 = 1;
const TEE_PARAM_TYPE_VALUE_OUTPUT: u8 = 2;
const TEE_PARAM_TYPE_VALUE_INOUT: u8 = 3;
const TEE_PARAM_TYPE_MEMREF_INPUT: u8 = 5;
const TEE_PARAM_TYPE_MEMREF_OUTPUT: u8 = 6;
const TEE_PARAM_TYPE_MEMREF_INOUT: u8 = 7;

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
    pub const TEE_NUM_PARAMS: usize = TEE_NUM_PARAMS;

    pub fn get_type(&self, index: usize) -> Result<TeeParamType, Errno> {
        let type_byte = match index {
            0 => self.types.type_0(),
            1 => self.types.type_1(),
            2 => self.types.type_2(),
            3 => self.types.type_3(),
            _ => return Err(Errno::EINVAL),
        };
        TeeParamType::try_from(type_byte).map_err(|_| Errno::EINVAL)
    }

    pub fn get_values(&self, index: usize) -> Result<Option<(u64, u64)>, Errno> {
        if self.get_type(index)? == TeeParamType::None {
            Ok(None)
        } else {
            let base_index = index * 2;
            Ok(Some((self.vals[base_index], self.vals[base_index + 1])))
        }
    }

    pub fn set_type(&mut self, index: usize, param_type: TeeParamType) -> Result<(), Errno> {
        match index {
            0 => self.types.set_type_0(param_type as u8),
            1 => self.types.set_type_1(param_type as u8),
            2 => self.types.set_type_2(param_type as u8),
            3 => self.types.set_type_3(param_type as u8),
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    }

    pub fn set_values(&mut self, index: usize, value_a: u64, value_b: u64) -> Result<(), Errno> {
        if index >= Self::TEE_NUM_PARAMS {
            return Err(Errno::EINVAL);
        }
        let base_index = index * 2;
        self.vals[base_index] = value_a;
        self.vals[base_index + 1] = value_b;
        Ok(())
    }

    pub fn new() -> Self {
        Self::default()
    }
}

/// Each parameter for TA invocation with copied content/buffer for safer operations.
/// This is our representation of `utee_params` and not for directly
/// interacting with OP-TEE TAs and clients (which expect pointers/references).
#[derive(Clone)]
pub enum UteeParamOwned {
    None,
    ValueInput { value_a: u64, value_b: u64 },
    ValueOutput,
    ValueInout { value_a: u64, value_b: u64 },
    MemrefInput { data: Box<[u8]> },
    MemrefOutput { buffer_size: usize },
    MemrefInout { data: Box<[u8]>, buffer_size: usize },
}

impl UteeParamOwned {
    pub const TEE_NUM_PARAMS: usize = UteeParams::TEE_NUM_PARAMS;
}

/// `utee_attribute` from `optee_os/lib/libutee/include/utee_types.h`
#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct UteeAttribute {
    pub a: u64,
    pub b: u64,
    pub attribute_id: TeeAttributeType,
    #[doc(hidden)]
    __pad: u32,
}

open_enum! {
    /// `TEE_ATTR_*` from `optee_os/lib/libutee/include/tee_api_defines.h`
    pub enum TeeAttributeType: u32 {
        SecretValue = 0xc000_0000,
        RsaModulus = 0xd000_0130,
        RsaPublicExponent = 0xd000_0230,
        RsaPrivateExponent = 0xc000_0330,
        RsaPrime1 = 0xc000_0430,
        RsaPrime2 = 0xc000_0530,
        RsaExponent1 = 0xc000_0630,
        RsaExponent2 = 0xc000_0730,
        RsaCoefficient = 0xc000_0830,
    }
}

/// `TEE_UUID` from `optee_os/lib/libutee/include/tee_api_types.h`. It uniquely identifies
/// TAs, cryptographic keys, and more.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug, FromBytes, Immutable, IntoBytes)]
#[repr(C)]
pub struct TeeUuid {
    pub time_low: u32,
    pub time_mid: u16,
    pub time_hi_and_version: u16,
    pub clock_seq_and_node: [u8; 8],
}

impl TeeUuid {
    /// Converts a UUID from a 16-byte array in RFC 4122 format (big-endian for numeric fields).
    ///
    /// The byte layout is:
    /// - bytes[0..4]: `time_low` (big-endian u32)
    /// - bytes[4..6]: `time_mid` (big-endian u16)
    /// - bytes[6..8]: `time_hi_and_version` (big-endian u16)
    /// - bytes[8..16]: `clock_seq_and_node` (8 bytes, direct copy)
    #[allow(clippy::missing_panics_doc)]
    pub fn from_bytes(data: [u8; 16]) -> Self {
        let time_low = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let time_mid = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let time_hi_and_version = u16::from_be_bytes(data[6..8].try_into().unwrap());
        let mut clock_seq_and_node = [0u8; 8];
        clock_seq_and_node.copy_from_slice(&data[8..16]);
        Self {
            time_low,
            time_mid,
            time_hi_and_version,
            clock_seq_and_node,
        }
    }

    /// Converts a UUID from OP-TEE's u64 array representation (Linux kernel format).
    ///
    /// The Linux kernel packs UUIDs as two little-endian u64 values via `export_uuid()`:
    /// ```c
    /// *a = get_unaligned_le64(p);      // bytes[0..8] as little-endian u64
    /// *b = get_unaligned_le64(p + 8);  // bytes[8..16] as little-endian u64
    /// ```
    pub fn from_u64_array(data: [u64; 2]) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&data[0].to_le_bytes());
        bytes[8..16].copy_from_slice(&data[1].to_le_bytes());
        Self::from_bytes(bytes)
    }
}

/// TA flags from `optee_os/lib/libutee/include/user_ta_header.h`.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct TaFlags(u32);

bitflags::bitflags! {
    impl TaFlags: u32 {
        /// TA has only one instance (deprecated flag, was USER_MODE)
        const USER_MODE = 0;
        /// TA executes from DDR (deprecated flag)
        const EXEC_DDR = 0;
        /// Only one TA instance exists at a time
        const SINGLE_INSTANCE = 0x0000_0004;
        /// Multiple sessions can share the instance
        const MULTI_SESSION = 0x0000_0008;
        /// Instance remains after last session closes
        const INSTANCE_KEEP_ALIVE = 0x0000_0010;
        /// TA accesses SDP memory
        const SECURE_DATA_PATH = 0x0000_0020;
        /// TA uses cache flush syscall
        const CACHE_MAINTENANCE = 0x0000_0080;
        /// TA can execute multiple sessions concurrently (pseudo-TAs only)
        const CONCURRENT = 0x0000_0100;
        /// Device enumeration at stage 1 (kernel driver init)
        const DEVICE_ENUM = 0x0000_0200;
        /// Device enumeration at stage 3 (with tee-supplicant)
        const DEVICE_ENUM_SUPP = 0x0000_0400;
        /// Don't close handle on corrupt object
        const DONT_CLOSE_HANDLE_ON_CORRUPT_OBJECT = 0x0000_0800;
        /// Device enumeration when TEE_STORAGE_PRIVATE is available
        const DEVICE_ENUM_TEE_STORAGE_PRIVATE = 0x0000_1000;
        /// Don't restart keep-alive TA if it crashed
        const INSTANCE_KEEP_CRASHED = 0x0000_2000;
    }
}

impl TaFlags {
    /// Returns true if this TA should only have one instance.
    pub fn is_single_instance(&self) -> bool {
        self.contains(TaFlags::SINGLE_INSTANCE)
    }

    /// Returns true if multiple sessions can share the TA instance.
    ///
    /// Note: This flag is only meaningful when `SINGLE_INSTANCE` is also set.
    /// For non-single-instance TAs, each session gets its own instance anyway.
    pub fn is_multi_session(&self) -> bool {
        self.contains(TaFlags::MULTI_SESSION)
    }

    /// Returns true if the TA instance should persist after all sessions close.
    ///
    /// Note: This flag is only meaningful when `SINGLE_INSTANCE` is also set.
    /// For non-single-instance TAs, instances are always destroyed when their session closes.
    pub fn is_keep_alive(&self) -> bool {
        self.contains(TaFlags::INSTANCE_KEEP_ALIVE)
    }
}

/// TA header structure from `optee_os/lib/libutee/include/user_ta_header.h`.
///
/// This structure is placed at the beginning of the `.ta_head` section in TA ELF binaries.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
#[repr(C)]
pub struct TaHead {
    /// TA UUID
    pub uuid: TeeUuid,
    /// Stack size in bytes
    pub stack_size: u32,
    /// TA flags (see `TaFlags`)
    pub flags: TaFlags,
    /// Deprecated entry point field
    pub depr_entry: u64,
}

/// Name of the ELF section containing the TA header.
pub const TA_HEAD_SECTION_NAME: &str = ".ta_head";

/// `TEE_Identity` from `optee_os/lib/libutee/include/tee_api_types.h`.
#[derive(Clone, Copy, PartialEq, Immutable, IntoBytes)]
#[repr(C)]
pub struct TeeIdentity {
    pub login: TeeLogin,
    pub uuid: TeeUuid,
}

/// `TEE_ObjectInfo` from `optee_os/lib/libutee/include/tee_api_types.h`
#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(C)]
pub struct TeeObjectInfo {
    pub object_type: TeeObjectType,
    pub object_size: u32,
    pub max_object_size: u32,
    pub object_usage: TeeUsage,
    pub data_size: u32,
    pub data_position: u32,
    pub handle_flags: TeeHandleFlag,
}

/// `TEE_USAGE_*` from `optee_os/lib/libutee/include/tee_api_defines.h`
#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct TeeUsage(u32);

bitflags::bitflags! {
    impl TeeUsage: u32 {
        const TEE_USAGE_EXTRACTABLE = 0x0000_0001;
        const TEE_USAGE_ENCRYPT = 0x0000_0002;
        const TEE_USAGE_DECRYPT = 0x0000_0004;
        const TEE_USAGE_MAC = 0x0000_0008;
        const TEE_USAGE_SIGN = 0x0000_0010;
        const TEE_USAGE_VERIFY = 0x0000_0020;
        const TEE_USAGE_DERIVE = 0x0000_0040;
    }
}

/// Memory access rights constants from `optee_os/lib/libutee/include/tee_api_defines.h`
#[derive(Clone, Copy, FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct TeeHandleFlag(u32);

bitflags::bitflags! {
    impl TeeHandleFlag: u32 {
        const TEE_HANDLE_FLAG_PERSISTENT = 0x0001_0000;
        const TEE_HANDLE_FLAG_INITIALIZED = 0x0002_0000;
        const TEE_HANDLE_FLAG_KEY_SET = 0x0004_0000;
        const TEE_HANDLE_FLAG_EXPECT_TWO_KEYS = 0x0008_0000;
    }
}

impl Default for TeeObjectInfo {
    fn default() -> Self {
        TeeObjectInfo {
            object_type: TeeObjectType::UNKNOWN,
            object_size: 0,
            max_object_size: 0,
            object_usage: TeeUsage::all(),
            data_size: 0,
            data_position: 0,
            handle_flags: TeeHandleFlag::empty(),
        }
    }
}

impl TeeObjectInfo {
    pub fn new(object_type: TeeObjectType, max_object_size: u32) -> Self {
        TeeObjectInfo {
            object_type,
            max_object_size,
            ..Default::default()
        }
    }
}

const TEE_LOGIN_PUBLIC: u32 = 0x0;
const TEE_LOGIN_USER: u32 = 0x1;
const TEE_LOGIN_GROUP: u32 = 0x2;
const TEE_LOGIN_APPLICATION: u32 = 0x4;
const TEE_LOGIN_APPLICATION_USER: u32 = 0x5;
const TEE_LOGIN_APPLICATION_GROUP: u32 = 0x6;
const TEE_LOGIN_TRUSTED_APP: u32 = 0xf000_0000;

/// `TEE Login type` from `optee_os/lib/libutee/include/tee_api_defines.h`
#[derive(Clone, Copy, PartialEq, TryFromPrimitive, Immutable, IntoBytes)]
#[repr(u32)]
pub enum TeeLogin {
    Public = TEE_LOGIN_PUBLIC,
    User = TEE_LOGIN_USER,
    Group = TEE_LOGIN_GROUP,
    Application = TEE_LOGIN_APPLICATION,
    ApplicationUser = TEE_LOGIN_APPLICATION_USER,
    ApplicationGroup = TEE_LOGIN_APPLICATION_GROUP,
    TrustedApp = TEE_LOGIN_TRUSTED_APP,
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

open_enum! {
    /// Origin code constants from `optee_os/lib/libutee/include/tee_api_defines.h`
    pub enum TeeOrigin: u32 {
        Api = 1,
        Comms = 2,
        Tee = 3,
        TrustedApp = 4,
    }
}

const TEE_PROPSET_TEE_IMPLEMENTATION: u32 = 0xffff_fffd;
const TEE_PROPSET_CURRENT_CLIENT: u32 = 0xffff_fffe;
const TEE_PROPSET_CURRENT_TA: u32 = 0xffff_ffff;

/// Property sets pseudo handles from `optee_os/lib/libutee/include/tee_api_defines.h`
#[derive(Clone, Copy, TryFromPrimitive, PartialEq)]
#[repr(u32)]
pub enum TeePropSet {
    TeeImplementation = TEE_PROPSET_TEE_IMPLEMENTATION,
    CurrentClient = TEE_PROPSET_CURRENT_CLIENT,
    CurrentTa = TEE_PROPSET_CURRENT_TA,
}

impl TeePropSet {
    pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
        u32::try_from(value)
            .map_err(|_| Errno::EINVAL)
            .and_then(|v| Self::try_from(v).map_err(|_| Errno::EINVAL))
    }
}

bitflags::bitflags! {
    /// Memory access rights constants from `optee_os/lib/libutee/include/tee_api_defines.h`
    #[non_exhaustive]
    #[derive(Clone, Copy)]
    pub struct TeeMemoryAccessRights: u32 {
        const TEE_MEMORY_ACCESS_READ = 0x1;
        const TEE_MEMORY_ACCESS_WRITE = 0x2;
        const TEE_MEMORY_ACCESS_ANY_OWNER = 0x4;
        const TEE_MEMORY_ACCESS_NONSECURE = 0x1000_0000;
        const TEE_MEMORY_ACCESS_SECURE = 0x2000_0000;
        const _ = !0;
    }
}

impl TeeMemoryAccessRights {
    pub fn try_from_usize(value: usize) -> Result<Self, Errno> {
        u32::try_from(value)
            .map_err(|_| Errno::EINVAL)
            .and_then(|v| Self::from_bits(v).ok_or(Errno::EINVAL))
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

const TEE_OPERATION_CIPHER: u32 = 1;
const TEE_OPERATION_MAC: u32 = 3;
const TEE_OPERATION_AE: u32 = 4;
const TEE_OPERATION_DIGEST: u32 = 5;
const TEE_OPERATION_ASYMMETRIC_CIPHER: u32 = 6;
const TEE_OPERATION_ASYMMETRIC_SIGNATURE: u32 = 7;
const TEE_OPERATION_KEY_DERIVATION: u32 = 8;

#[derive(Clone, Copy, TryFromPrimitive, PartialEq)]
#[repr(u32)]
pub enum TeeAlgorithmClass {
    Cipher = TEE_OPERATION_CIPHER,
    Mac = TEE_OPERATION_MAC,
    Aead = TEE_OPERATION_AE,
    Digest = TEE_OPERATION_DIGEST,
    AsymmetricCipher = TEE_OPERATION_ASYMMETRIC_CIPHER,
    AsymmetricSignature = TEE_OPERATION_ASYMMETRIC_SIGNATURE,
    KeyDerivation = TEE_OPERATION_KEY_DERIVATION,
    Unknown = 0xffff_ffff,
}

impl From<TeeAlgorithm> for TeeAlgorithmClass {
    fn from(algo: TeeAlgorithm) -> Self {
        match algo {
            TeeAlgorithm::AesCtr | TeeAlgorithm::AesGcm => TeeAlgorithmClass::Cipher,
            TeeAlgorithm::HmacSha256 | TeeAlgorithm::HmacSha512 => TeeAlgorithmClass::Mac,
            TeeAlgorithm::RsaPkcs1Sha256 | TeeAlgorithm::RsaPkcs1Sha512 => {
                TeeAlgorithmClass::AsymmetricSignature
            }
            _ => TeeAlgorithmClass::Unknown,
        }
    }
}

open_enum! {
    /// Object types `optee_os/lib/libutee/include/tee_api_defines.h`
    /// TEE_TYPE_*
    /// TODO: add more object types as needed
    pub enum TeeObjectType: u32 {
        Aes = 0xa000_0010,
        HmacSha256 = 0xa000_0004,
        HmacSha512 = 0xa000_0006,
        RsaPublicKey = 0xa000_0030,
        RsaKeypair = 0xa100_0030,
        GenericSecret = 0xa000_0000,
        CorruptedObject = 0xa000_00be,
        Data = 0xa000_00bf,
    }
}
impl TeeObjectType {
    // Not explicitly defined in OP-TEE, but we define it for convenience _within_ this module. We
    // don't define it in the open_enum! macro to avoid exposing it outside this module.
    const UNKNOWN: Self = TeeObjectType(0xffff_ffff);
}

const TEE_SUCCESS: u32 = 0x0000_0000;
const TEE_ERROR_CORRUPT_OBJECT: u32 = 0xf010_0001;
const TEE_ERROR_CORRUPT_OBJECT_2: u32 = 0xf010_0002;
const TEE_ERROR_STORAGE_NOT_AVAILABLE: u32 = 0xf010_0003;
const TEE_ERROR_STORAGE_NOT_AVAILABLE_2: u32 = 0xf010_0004;
const TEE_ERROR_CIPHERTEXT_INVALID: u32 = 0xf010_0006;
const TEE_ERROR_GENERIC: u32 = 0xffff_0000;
const TEE_ERROR_ACCESS_DENIED: u32 = 0xffff_0001;
const TEE_ERROR_CANCEL: u32 = 0xffff_0002;
const TEE_ERROR_ACCESS_CONFLICT: u32 = 0xffff_0003;
const TEE_ERROR_EXCESS_DATA: u32 = 0xffff_0004;
const TEE_ERROR_BAD_FORMAT: u32 = 0xffff_0005;
const TEE_ERROR_BAD_PARAMETERS: u32 = 0xffff_0006;
const TEE_ERROR_BAD_STATE: u32 = 0xffff_0007;
const TEE_ERROR_ITEM_NOT_FOUND: u32 = 0xffff_0008;
const TEE_ERROR_NOT_IMPLEMENTED: u32 = 0xffff_0009;
const TEE_ERROR_NOT_SUPPORTED: u32 = 0xffff_000a;
const TEE_ERROR_NO_DATA: u32 = 0xffff_000b;
const TEE_ERROR_OUT_OF_MEMORY: u32 = 0xffff_000c;
const TEE_ERROR_BUSY: u32 = 0xffff_000d;
const TEE_ERROR_COMMUNICATION: u32 = 0xffff_000e;
const TEE_ERROR_SECURITY: u32 = 0xffff_000f;
const TEE_ERROR_SHORT_BUFFER: u32 = 0xffff_0010;
const TEE_ERROR_EXTERNAL_CANCEL: u32 = 0xffff_0011;
const TEE_ERROR_OVERFLOW: u32 = 0xffff_300f;
const TEE_ERROR_TARGET_DEAD: u32 = 0xffff_3024;
const TEE_ERROR_STORAGE_NO_SPACE: u32 = 0xffff_3041;
const TEE_ERROR_MAC_INVALID: u32 = 0xffff_3071;
const TEE_ERROR_SIGNATURE_INVALID: u32 = 0xffff_3072;
const TEE_ERROR_TIME_NOT_SET: u32 = 0xffff_5000;
const TEE_ERROR_TIME_NEEDS_RESET: u32 = 0xffff_5001;

/// `TEE_Result` (API error codes) from `optee_os/lib/libutee/include/tee_api_defines.h`
#[derive(Clone, Copy, TryFromPrimitive, PartialEq, Debug)]
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
}

impl From<TeeResult> for u32 {
    fn from(res: TeeResult) -> Self {
        res as u32
    }
}

const UTEE_ENTRY_FUNC_OPEN_SESSION: u32 = 0;
const UTEE_ENTRY_FUNC_CLOSE_SESSION: u32 = 1;
const UTEE_ENTRY_FUNC_INVOKE_COMMAND: u32 = 2;

#[derive(Clone, Copy, TryFromPrimitive, PartialEq)]
#[repr(u32)]
pub enum UteeEntryFunc {
    OpenSession = UTEE_ENTRY_FUNC_OPEN_SESSION,
    CloseSession = UTEE_ENTRY_FUNC_CLOSE_SESSION,
    InvokeCommand = UTEE_ENTRY_FUNC_INVOKE_COMMAND,
    Unknown = 0xffff_ffff,
}

const USER_TA_PROP_TYPE_BOOL: u32 = 0;
const USER_TA_PROP_TYPE_U32: u32 = 1;
const USER_TA_PROP_TYPE_UUID: u32 = 2;
const USER_TA_PROP_TYPE_IDENTITY: u32 = 3;
const USER_TA_PROP_TYPE_STRING: u32 = 4;
const USER_TA_PROP_TYPE_BINARY_BLOCK: u32 = 5;

/// USER_TA_PROP_TYPE_* from lib/libutee/include/user_ta_header.h
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum UserTaPropType {
    Bool = USER_TA_PROP_TYPE_BOOL,
    U32 = USER_TA_PROP_TYPE_U32,
    Uuid = USER_TA_PROP_TYPE_UUID,
    Identity = USER_TA_PROP_TYPE_IDENTITY,
    String = USER_TA_PROP_TYPE_STRING,
    BinaryBlock = USER_TA_PROP_TYPE_BINARY_BLOCK,
}

#[non_exhaustive]
pub enum LdelfSyscallRequest<Platform: litebox::platform::RawPointerProvider> {
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
    MapZi {
        va: Platform::RawMutPointer<usize>,
        num_bytes: usize,
        pad_begin: usize,
        pad_end: usize,
        flags: LdelfMapFlags,
    },
    Unmap {
        va: Platform::RawMutPointer<u8>,
        num_bytes: usize,
    },
    OpenBin {
        uuid: Platform::RawConstPointer<TeeUuid>,
        uuid_size: usize,
        handle: Platform::RawMutPointer<u32>,
    },
    CloseBin {
        handle: u32,
    },
    MapBin {
        va: Platform::RawMutPointer<usize>,
        num_bytes: usize,
        handle: u32,
        offs: usize,
        pad_begin: usize,
        pad_end: usize,
        flags: LdelfMapFlags,
    },
    CpFromBin {
        dst: usize,
        offs: usize,
        num_bytes: usize,
        handle: u32,
    },
    GenRndNum {
        buf: Platform::RawMutPointer<u8>,
        num_bytes: usize,
    },
}

impl<Platform: litebox::platform::RawPointerProvider> LdelfSyscallRequest<Platform> {
    pub fn try_from_raw(syscall_number: usize, ctx: &PtRegs) -> Result<Self, Errno> {
        let ctx = SyscallContext::from_pt_regs(ctx);
        let sysnr = u32::try_from(syscall_number).map_err(|_| Errno::ENOSYS)?;
        let dispatcher = match LdelfSyscallNr::try_from(sysnr).unwrap_or(LdelfSyscallNr::Unknown) {
            LdelfSyscallNr::Return => LdelfSyscallRequest::Return {
                ret: ctx.syscall_arg(0),
            },
            LdelfSyscallNr::Log => LdelfSyscallRequest::Log {
                buf: Platform::RawConstPointer::from_usize(ctx.syscall_arg(0)),
                len: ctx.syscall_arg(1),
            },
            LdelfSyscallNr::Panic => LdelfSyscallRequest::Panic {
                code: ctx.syscall_arg(0),
            },
            LdelfSyscallNr::MapZi => LdelfSyscallRequest::MapZi {
                va: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                num_bytes: ctx.syscall_arg(1),
                pad_begin: ctx.syscall_arg(2),
                pad_end: ctx.syscall_arg(3),
                flags: LdelfMapFlags::from_bits_retain(ctx.syscall_arg(4)),
            },
            LdelfSyscallNr::Unmap => LdelfSyscallRequest::Unmap {
                va: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                num_bytes: ctx.syscall_arg(1),
            },
            LdelfSyscallNr::OpenBin => LdelfSyscallRequest::OpenBin {
                uuid: Platform::RawConstPointer::from_usize(ctx.syscall_arg(0)),
                uuid_size: ctx.syscall_arg(1),
                handle: Platform::RawMutPointer::from_usize(ctx.syscall_arg(2)),
            },
            LdelfSyscallNr::CloseBin => LdelfSyscallRequest::CloseBin {
                handle: u32::try_from(ctx.syscall_arg(0)).map_err(|_| Errno::EINVAL)?,
            },
            LdelfSyscallNr::MapBin => LdelfSyscallRequest::MapBin {
                va: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                num_bytes: ctx.syscall_arg(1),
                handle: u32::try_from(ctx.syscall_arg(2)).map_err(|_| Errno::EINVAL)?,
                offs: ctx.syscall_arg(3),
                pad_begin: ctx.syscall_arg(4),
                pad_end: ctx.syscall_arg(5),
                flags: LdelfMapFlags::from_bits_retain(ctx.syscall_arg(6)),
            },
            LdelfSyscallNr::CpFromBin => LdelfSyscallRequest::CpFromBin {
                dst: ctx.syscall_arg(0),
                offs: ctx.syscall_arg(1),
                num_bytes: ctx.syscall_arg(2),
                handle: u32::try_from(ctx.syscall_arg(3)).map_err(|_| Errno::EINVAL)?,
            },
            LdelfSyscallNr::GenRndNum => LdelfSyscallRequest::GenRndNum {
                buf: Platform::RawMutPointer::from_usize(ctx.syscall_arg(0)),
                num_bytes: ctx.syscall_arg(1),
            },
            _ => todo!("implement ldelf syscall number: {}", sysnr),
        };

        Ok(dispatcher)
    }
}

bitflags::bitflags! {
    /// `LDELF_MAP_FLAG_*` from `optee_os/ldelf/include/ldelf.h`
    #[non_exhaustive]
    #[derive(Clone, Copy, Debug)]
    pub struct LdelfMapFlags: usize {
        const LDELF_MAP_FLAG_SHAREABLE = 0x1;
        const LDELF_MAP_FLAG_WRITEABLE = 0x2;
        const LDELF_MAP_FLAG_EXECUTABLE = 0x4;
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// `TEE_MATTR_*` from `optee_os/core/include/mm/tee_mmu_types.h`
    #[non_exhaustive]
    #[derive(Clone, Copy, Debug)]
    pub struct TeeMemAttr: usize {
        const TEE_MATTR_VALID_BLOCK = 0x1;
        const TEE_MATTR_TABLE = 0x8;
        const TEE_MATTR_PR = 0x10;
        const TEE_MATTR_PW = 0x20;
        const TEE_MATTR_PX = 0x40;
        const TEE_MATTR_PRW = Self::TEE_MATTR_PR.bits() | Self::TEE_MATTR_PW.bits();
        const TEE_MATTR_PRWX = Self::TEE_MATTR_PRW.bits() | Self::TEE_MATTR_PX.bits();
        const TEE_MATTR_UR = 0x80;
        const TEE_MATTR_UW = 0x100;
        const TEE_MATTR_UX = 0x200;
        const TEE_MATTR_URW = Self::TEE_MATTR_UR.bits() | Self::TEE_MATTR_UW.bits();
        const TEE_MATTR_URWX = Self::TEE_MATTR_URW.bits() | Self::TEE_MATTR_UX.bits();
        const TEE_MATTR_PROT_MASK = Self::TEE_MATTR_PRWX.bits() | Self::TEE_MATTR_URWX.bits();
        const TEE_MATTR_GLOBAL = 0x400;
        const TEE_MATTR_SECURE = 0x800;
        const _ = !0;
    }
}

/// `ldef_arg` from `optee_os/ldelf/include/ldelf.h`
#[derive(Clone, Copy, Default, FromBytes, Immutable, IntoBytes)]
#[repr(C)]
pub struct LdelfArg {
    pub uuid: TeeUuid,
    pub is_32bit: u32,
    pub flags: u32,
    pub entry_func: u64,
    pub stack_ptr: u64,
    pub dump_entry: u64,
    pub ftrace_entry: u64,
    pub dl_entry: u64,
    pub fbuf: u64,
}

impl LdelfArg {
    pub fn new(ta_uuid: TeeUuid) -> Self {
        Self {
            uuid: ta_uuid,
            ..Default::default()
        }
    }
}

const OPTEE_MSG_CMD_OPEN_SESSION: u32 = 0;
const OPTEE_MSG_CMD_INVOKE_COMMAND: u32 = 1;
const OPTEE_MSG_CMD_CLOSE_SESSION: u32 = 2;
const OPTEE_MSG_CMD_CANCEL: u32 = 3;
const OPTEE_MSG_CMD_REGISTER_SHM: u32 = 4;
const OPTEE_MSG_CMD_UNREGISTER_SHM: u32 = 5;
const OPTEE_MSG_CMD_DO_BOTTOM_HALF: u32 = 6;
const OPTEE_MSG_CMD_STOP_ASYNC_NOTIF: u32 = 7;

/// `OPTEE_MSG_CMD_*` from `optee_os/core/include/optee_msg.h`
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum OpteeMessageCommand {
    OpenSession = OPTEE_MSG_CMD_OPEN_SESSION,
    InvokeCommand = OPTEE_MSG_CMD_INVOKE_COMMAND,
    CloseSession = OPTEE_MSG_CMD_CLOSE_SESSION,
    Cancel = OPTEE_MSG_CMD_CANCEL,
    RegisterShm = OPTEE_MSG_CMD_REGISTER_SHM,
    UnregisterShm = OPTEE_MSG_CMD_UNREGISTER_SHM,
    DoBottomHalf = OPTEE_MSG_CMD_DO_BOTTOM_HALF,
    StopAsyncNotif = OPTEE_MSG_CMD_STOP_ASYNC_NOTIF,
}

impl TryFrom<OpteeMessageCommand> for UteeEntryFunc {
    type Error = OpteeSmcReturnCode;
    fn try_from(cmd: OpteeMessageCommand) -> Result<Self, Self::Error> {
        match cmd {
            OpteeMessageCommand::OpenSession => Ok(UteeEntryFunc::OpenSession),
            OpteeMessageCommand::CloseSession => Ok(UteeEntryFunc::CloseSession),
            OpteeMessageCommand::InvokeCommand => Ok(UteeEntryFunc::InvokeCommand),
            _ => Err(OpteeSmcReturnCode::EBadCmd),
        }
    }
}

/// Temporary memory reference parameter
///
/// `optee_msg_param_tmem` from `optee_os/core/include/optee_msg.h`
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct OpteeMsgParamTmem {
    /// Physical address of the buffer
    pub buf_ptr: u64,
    /// Size of the buffer
    pub size: u64,
    /// Temporary shared memory reference or identifier
    pub shm_ref: u64,
}

/// Registered memory reference parameter
///
/// `optee_msg_param_rmem` from `optee_os/core/include/optee_msg.h`
#[derive(Clone, Copy)]
#[repr(C)]
pub struct OpteeMsgParamRmem {
    /// Offset into shared memory reference
    pub offs: u64,
    /// Size of the buffer
    pub size: u64,
    /// Shared memory reference or identifier
    pub shm_ref: u64,
}

/// FF-A memory reference parameter
///
/// `optee_msg_param_fmem` from `optee_os/core/include/optee_msg.h`
///
/// Note: LiteBox doesn't currently support FF-A shared memory, so this struct is
/// provided for completeness but is not used.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct OpteeMsgParamFmem {
    /// Lower bits of offset into shared memory reference
    pub offs_low: u32,
    /// Higher bits of offset into shared memory reference
    pub offs_high: u16,
    /// Internal offset into the first page of shared memory reference
    pub internal_offs: u16,
    /// Size of the buffer
    pub size: u64,
    /// Global identifier of the shared memory
    pub global_id: u64,
}

/// Opaque value parameter
/// Value parameters are passed unchecked between normal and secure world.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct OpteeMsgParamValue {
    pub a: u64,
    pub b: u64,
    pub c: u64,
}

/// Parameter used together with `OpteeMsgArgs`
#[derive(Clone, Copy)]
#[repr(C)]
pub union OpteeMsgParamUnion {
    tmem: OpteeMsgParamTmem,
    rmem: OpteeMsgParamRmem,
    fmem: OpteeMsgParamFmem,
    value: OpteeMsgParamValue,
    octets: [u8; 24],
}

const OPTEE_MSG_ATTR_TYPE_NONE: u8 = 0x0;
const OPTEE_MSG_ATTR_TYPE_VALUE_INPUT: u8 = 0x1;
const OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT: u8 = 0x2;
const OPTEE_MSG_ATTR_TYPE_VALUE_INOUT: u8 = 0x3;
const OPTEE_MSG_ATTR_TYPE_RMEM_INPUT: u8 = 0x5;
const OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT: u8 = 0x6;
const OPTEE_MSG_ATTR_TYPE_RMEM_INOUT: u8 = 0x7;
const OPTEE_MSG_ATTR_TYPE_TMEM_INPUT: u8 = 0x9;
const OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT: u8 = 0xa;
const OPTEE_MSG_ATTR_TYPE_TMEM_INOUT: u8 = 0xb;
// Note: `OPTEE_MSG_ATTR_TYPE_FMEM_*` are aliases of `OPTEE_MSG_ATTR_TYPE_RMEM_*`.
// Whether it is RMEM of FMEM depends on the conduit.

#[non_exhaustive]
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum OpteeMsgAttrType {
    None = OPTEE_MSG_ATTR_TYPE_NONE,
    ValueInput = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT,
    ValueOutput = OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT,
    ValueInout = OPTEE_MSG_ATTR_TYPE_VALUE_INOUT,
    RmemInput = OPTEE_MSG_ATTR_TYPE_RMEM_INPUT,
    RmemOutput = OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT,
    RmemInout = OPTEE_MSG_ATTR_TYPE_RMEM_INOUT,
    TmemInput = OPTEE_MSG_ATTR_TYPE_TMEM_INPUT,
    TmemOutput = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT,
    TmemInout = OPTEE_MSG_ATTR_TYPE_TMEM_INOUT,
}

#[non_exhaustive]
#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct OpteeMsgAttr {
    pub typ: B8,
    pub meta: bool,
    pub noncontig: bool,
    #[skip]
    __: B54,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct OpteeMsgParam {
    attr: OpteeMsgAttr,
    u: OpteeMsgParamUnion,
}

impl OpteeMsgParam {
    pub fn attr_type(&self) -> OpteeMsgAttrType {
        OpteeMsgAttrType::try_from(self.attr.typ()).unwrap_or(OpteeMsgAttrType::None)
    }
    pub fn get_param_tmem(&self) -> Option<OpteeMsgParamTmem> {
        if matches!(
            self.attr.typ(),
            OPTEE_MSG_ATTR_TYPE_TMEM_INPUT
                | OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT
                | OPTEE_MSG_ATTR_TYPE_TMEM_INOUT
        ) {
            Some(unsafe { self.u.tmem })
        } else {
            None
        }
    }
    pub fn get_param_rmem(&self) -> Option<OpteeMsgParamRmem> {
        if matches!(
            self.attr.typ(),
            OPTEE_MSG_ATTR_TYPE_RMEM_INPUT
                | OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT
                | OPTEE_MSG_ATTR_TYPE_RMEM_INOUT
        ) {
            Some(unsafe { self.u.rmem })
        } else {
            None
        }
    }
    pub fn get_param_fmem(&self) -> Option<OpteeMsgParamFmem> {
        if matches!(
            self.attr.typ(),
            OPTEE_MSG_ATTR_TYPE_RMEM_INPUT
                | OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT
                | OPTEE_MSG_ATTR_TYPE_RMEM_INOUT
        ) {
            Some(unsafe { self.u.fmem })
        } else {
            None
        }
    }
    pub fn get_param_value(&self) -> Option<OpteeMsgParamValue> {
        if matches!(
            self.attr.typ(),
            OPTEE_MSG_ATTR_TYPE_VALUE_INPUT
                | OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT
                | OPTEE_MSG_ATTR_TYPE_VALUE_INOUT
        ) {
            Some(unsafe { self.u.value })
        } else {
            None
        }
    }
}

/// `optee_msg_arg` from `optee_os/core/include/optee_msg.h`
/// OP-TEE message argument structure that the normal world (or VTL0) OP-TEE driver and OP-TEE OS use to
/// exchange messages.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct OpteeMsgArgs {
    /// OP-TEE message command. This is a superset of `UteeEntryFunc`.
    pub cmd: OpteeMessageCommand,
    /// TA function ID which is used if `cmd == InvokeCommand`. Note that the meaning of `cmd` and `func`
    /// is swapped compared to TAs.
    pub func: u32,
    /// Session ID. This is "IN" parameter most of the time except for `cmd == OpenSession` where
    /// the secure world generates and returns a session ID.
    pub session: u32,
    /// Cancellation ID. This is a unique value to identify this request.
    pub cancel_id: u32,
    pad: u32,
    /// Return value from the secure world
    pub ret: TeeResult,
    /// Origin of the return value
    pub ret_origin: TeeOrigin,
    /// Number of parameters contained in `params`
    pub num_params: u32,
    /// Parameters to be passed to the secure world. If `cmd == OpenSession`, the first two params contain
    /// a TA UUID and they are not delivered to the TA.
    /// Note that, originally, the length of this array is variable. We fix it to `TEE_NUM_PARAMS + 2` to
    /// simplify the implementation (our OP-TEE Shim supports up to four parameters as well).
    ///
    /// TODO: To support OP-TEE RPC, we should make this array length dynamic. Consider to use
    /// a trailing unsized slice (DST) or other mechanisms.
    pub params: [OpteeMsgParam; TEE_NUM_PARAMS + 2],
}

impl OpteeMsgArgs {
    /// Validate the message argument structure.
    pub fn validate(&self) -> Result<(), OpteeSmcReturnCode> {
        let _ = OpteeMessageCommand::try_from(self.cmd as u32)
            .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;
        if self.cmd == OpteeMessageCommand::OpenSession && self.num_params < 2 {
            return Err(OpteeSmcReturnCode::EBadCmd);
        }
        if self.num_params as usize > self.params.len() {
            Err(OpteeSmcReturnCode::EBadCmd)
        } else {
            Ok(())
        }
    }
    pub fn get_param_tmem(&self, index: usize) -> Result<OpteeMsgParamTmem, OpteeSmcReturnCode> {
        if index >= self.num_params as usize {
            Err(OpteeSmcReturnCode::ENotAvail)
        } else {
            Ok(self.params[index]
                .get_param_tmem()
                .ok_or(OpteeSmcReturnCode::EBadCmd)?)
        }
    }
    pub fn get_param_rmem(&self, index: usize) -> Result<OpteeMsgParamRmem, OpteeSmcReturnCode> {
        if index >= self.num_params as usize {
            Err(OpteeSmcReturnCode::ENotAvail)
        } else {
            Ok(self.params[index]
                .get_param_rmem()
                .ok_or(OpteeSmcReturnCode::EBadCmd)?)
        }
    }
    pub fn get_param_fmem(&self, index: usize) -> Result<OpteeMsgParamFmem, OpteeSmcReturnCode> {
        if index >= self.num_params as usize {
            Err(OpteeSmcReturnCode::ENotAvail)
        } else {
            Ok(self.params[index]
                .get_param_fmem()
                .ok_or(OpteeSmcReturnCode::EBadCmd)?)
        }
    }
    pub fn get_param_value(&self, index: usize) -> Result<OpteeMsgParamValue, OpteeSmcReturnCode> {
        if index >= self.num_params as usize {
            Err(OpteeSmcReturnCode::ENotAvail)
        } else {
            Ok(self.params[index]
                .get_param_value()
                .ok_or(OpteeSmcReturnCode::EBadCmd)?)
        }
    }
    pub fn set_param_value(
        &mut self,
        index: usize,
        value: OpteeMsgParamValue,
    ) -> Result<(), OpteeSmcReturnCode> {
        if index >= self.num_params as usize {
            Err(OpteeSmcReturnCode::ENotAvail)
        } else {
            self.params[index].u.value = value;
            Ok(())
        }
    }

    /// Set the size field for a memref parameter (rmem or tmem).
    /// This updates `rmem.size` or `tmem.size` which share the same offset as `value.b` in the union.
    pub fn set_param_memref_size(
        &mut self,
        index: usize,
        size: u64,
    ) -> Result<(), OpteeSmcReturnCode> {
        if index >= self.num_params as usize {
            Err(OpteeSmcReturnCode::ENotAvail)
        } else {
            // rmem.size and tmem.size are at the same offset as value.b in the union
            self.params[index].u.rmem.size = size;
            Ok(())
        }
    }
}

/// A memory page to exchange OP-TEE SMC call arguments.
/// OP-TEE assumes that the underlying architecture is Arm with TrustZone and
/// thus it uses Secure Monitor Call (SMC) calling convention (SMCCC).
/// Since we currently rely on the existing OP-TEE driver which assumes SMCCC, we translate it into
/// our VTL switch convention.
/// Specifically, OP-TEE SMC call uses up to nine CPU registers to pass arguments.
/// However, since VTL call only supports up to four parameters, we allocate a VTL0 memory page and
/// exchange all arguments through that memory page.
/// TODO: Since this is LVBS-specific structure to facilitate the translation between VTL call convention,
/// we might want to move it to the `litebox_platform_lvbs` crate later.
/// Also, we might need to document how to inteprete this structure by referencing `optee_smc.h` and
/// Arm's SMCCC.
#[repr(align(4096))]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct OpteeSmcArgsPage {
    pub args: [usize; Self::NUM_OPTEE_SMC_ARGS],
}
impl OpteeSmcArgsPage {
    const NUM_OPTEE_SMC_ARGS: usize = 9;
}

impl From<&OpteeSmcArgsPage> for OpteeSmcArgs {
    fn from(page: &OpteeSmcArgsPage) -> Self {
        let mut smc = OpteeSmcArgs::default();
        smc.args.copy_from_slice(&page.args);
        smc
    }
}

/// OP-TEE SMC call arguments.
#[derive(Clone, Copy, Default)]
pub struct OpteeSmcArgs {
    args: [usize; Self::NUM_OPTEE_SMC_ARGS],
}

impl OpteeSmcArgs {
    const NUM_OPTEE_SMC_ARGS: usize = 9;

    /// Get the function ID of an OP-TEE SMC call
    pub fn func_id(&self) -> Result<OpteeSmcFunction, OpteeSmcReturnCode> {
        OpteeSmcFunction::try_from(self.args[0] & OpteeSmcFunction::MASK)
            .map_err(|_| OpteeSmcReturnCode::EBadCmd)
    }

    /// Get the physical address of `OpteeMsgArgs`. The secure world is expected to map and copy
    /// this structure.
    pub fn optee_msg_args_phys_addr(&self) -> Result<u64, OpteeSmcReturnCode> {
        // To avoid potential sign extension and overflow issues, OP-TEE stores the low and
        // high 32 bits of a 64-bit address in `args[2]` and `args[1]`, respectively.
        if self.args[1] & 0xffff_ffff_0000_0000 == 0 && self.args[2] & 0xffff_ffff_0000_0000 == 0 {
            let addr = (self.args[1] << 32) | self.args[2];
            Ok(addr as u64)
        } else {
            Err(OpteeSmcReturnCode::EBadAddr)
        }
    }

    /// Set the return code of an OP-TEE SMC call
    pub fn set_return_code(&mut self, code: OpteeSmcReturnCode) {
        self.args[0] = code as usize;
    }
}

/// `OPTEE_SMC_FUNCID_*` from `core/arch/arm/include/sm/optee_smc.h`
/// TODO: Add stuffs based on the OP-TEE driver that LVBS is using.
const OPTEE_SMC_FUNCID_GET_OS_UUID: usize = 0x0;
const OPTEE_SMC_FUNCID_GET_OS_REVISION: usize = 0x1;
const OPTEE_SMC_FUNCID_CALL_WITH_ARG: usize = 0x4;
const OPTEE_SMC_FUNCID_EXCHANGE_CAPABILITIES: usize = 0x9;
const OPTEE_SMC_FUNCID_DISABLE_SHM_CACHE: usize = 0xa;
const OPTEE_SMC_FUNCID_CALL_WITH_RPC_ARG: usize = 0x12;
const OPTEE_SMC_FUNCID_CALL_WITH_REGD_ARG: usize = 0x13;
const OPTEE_SMC_FUNCID_CALLS_UID: usize = 0xff01;
const OPTEE_SMC_FUNCID_CALLS_REVISION: usize = 0xff03;

#[non_exhaustive]
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(usize)]
pub enum OpteeSmcFunction {
    GetOsUuid = OPTEE_SMC_FUNCID_GET_OS_UUID,
    GetOsRevision = OPTEE_SMC_FUNCID_GET_OS_REVISION,
    CallWithArg = OPTEE_SMC_FUNCID_CALL_WITH_ARG,
    ExchangeCapabilities = OPTEE_SMC_FUNCID_EXCHANGE_CAPABILITIES,
    DisableShmCache = OPTEE_SMC_FUNCID_DISABLE_SHM_CACHE,
    CallWithRpcArg = OPTEE_SMC_FUNCID_CALL_WITH_RPC_ARG,
    CallWithRegdArg = OPTEE_SMC_FUNCID_CALL_WITH_REGD_ARG,
    CallsUid = OPTEE_SMC_FUNCID_CALLS_UID,
    CallsRevision = OPTEE_SMC_FUNCID_CALLS_REVISION,
}

impl OpteeSmcFunction {
    const MASK: usize = 0xffff;
}

/// OP-TEE SMC call result.
/// OP-TEE SMC call uses CPU registers to pass input and output values.
/// Thus, we convert this into `OpteeSmcArgs` later.
#[non_exhaustive]
pub enum OpteeSmcResult<'a> {
    Generic {
        status: OpteeSmcReturnCode,
    },
    ExchangeCapabilities {
        status: OpteeSmcReturnCode,
        capabilities: OpteeSecureWorldCapabilities,
        max_notif_value: usize,
        data: usize,
    },
    Uuid {
        data: &'a [u32; 4],
    },
    Revision {
        major: usize,
        minor: usize,
    },
    OsRevision {
        major: usize,
        minor: usize,
        build_id: usize,
    },
    DisableShmCache {
        status: OpteeSmcReturnCode,
        shm_upper32: usize,
        shm_lower32: usize,
    },
    CallWithArg {
        msg_args: Box<OpteeMsgArgs>,
    },
}

impl From<OpteeSmcResult<'_>> for OpteeSmcArgs {
    fn from(value: OpteeSmcResult) -> Self {
        match value {
            OpteeSmcResult::Generic { status } => {
                let mut smc = OpteeSmcArgs::default();
                smc.args[0] = status as usize;
                smc
            }
            OpteeSmcResult::ExchangeCapabilities {
                status,
                capabilities,
                max_notif_value,
                data,
            } => {
                let mut smc = OpteeSmcArgs::default();
                smc.args[0] = status as usize;
                smc.args[1] = capabilities.bits();
                smc.args[2] = max_notif_value;
                smc.args[3] = data;
                smc
            }
            OpteeSmcResult::Uuid { data } => {
                let mut smc = OpteeSmcArgs::default();
                for (i, arg) in smc.args.iter_mut().enumerate().take(4) {
                    *arg = data[i] as usize;
                }
                smc
            }
            OpteeSmcResult::Revision { major, minor } => {
                let mut smc = OpteeSmcArgs::default();
                smc.args[0] = major;
                smc.args[1] = minor;
                smc
            }
            OpteeSmcResult::OsRevision {
                major,
                minor,
                build_id,
            } => {
                let mut smc = OpteeSmcArgs::default();
                smc.args[0] = major;
                smc.args[1] = minor;
                smc.args[2] = build_id;
                smc
            }
            OpteeSmcResult::DisableShmCache {
                status,
                shm_upper32,
                shm_lower32,
            } => {
                let mut smc = OpteeSmcArgs::default();
                smc.args[0] = status as usize;
                smc.args[1] = shm_upper32;
                smc.args[2] = shm_lower32;
                smc
            }
            OpteeSmcResult::CallWithArg { .. } => {
                panic!(
                    "OpteeSmcResult::CallWithArg cannot be converted to OpteeSmcArgs directly. Handle the incorporated OpteeMsgArgs."
                );
            }
        }
    }
}

bitflags::bitflags! {
    #[non_exhaustive]
    #[derive(PartialEq, Clone, Copy)]
    pub struct OpteeSecureWorldCapabilities: usize {
        const HAVE_RESERVED_SHM = 1 << 0;
        const UNREGISTERED_SHM = 1 << 1;
        const DYNAMIC_SHM = 1 << 2;
        const MEMREF_NULL = 1 << 4;
        const RPC_ARG = 1 << 6;
        const _ = !0;
    }
}

const OPTEE_SMC_RETURN_OK: usize = 0x0;
const OPTEE_SMC_RETURN_ETHREAD_LIMIT: usize = 0x1;
const OPTEE_SMC_RETURN_EBUSY: usize = 0x2;
const OPTEE_SMC_RETURN_ERESUME: usize = 0x3;
const OPTEE_SMC_RETURN_EBADADDR: usize = 0x4;
const OPTEE_SMC_RETURN_EBADCMD: usize = 0x5;
const OPTEE_SMC_RETURN_ENOMEM: usize = 0x6;
const OPTEE_SMC_RETURN_ENOTAVAIL: usize = 0x7;
const OPTEE_SMC_RETURN_UNKNOWN_FUNCTION: usize = 0xffff_ffff;

#[non_exhaustive]
#[derive(Copy, Clone, PartialEq, TryFromPrimitive)]
#[repr(usize)]
pub enum OpteeSmcReturnCode {
    Ok = OPTEE_SMC_RETURN_OK,
    EThreadLimit = OPTEE_SMC_RETURN_ETHREAD_LIMIT,
    EBusy = OPTEE_SMC_RETURN_EBUSY,
    EResume = OPTEE_SMC_RETURN_ERESUME,
    EBadAddr = OPTEE_SMC_RETURN_EBADADDR,
    EBadCmd = OPTEE_SMC_RETURN_EBADCMD,
    ENomem = OPTEE_SMC_RETURN_ENOMEM,
    ENotAvail = OPTEE_SMC_RETURN_ENOTAVAIL,
    UnknownFunction = OPTEE_SMC_RETURN_UNKNOWN_FUNCTION,
}

impl From<litebox_common_linux::vmap::PhysPointerError> for OpteeSmcReturnCode {
    fn from(err: litebox_common_linux::vmap::PhysPointerError) -> Self {
        use litebox_common_linux::vmap::PhysPointerError;
        match err {
            PhysPointerError::AlreadyMapped(_) => OpteeSmcReturnCode::EBusy,
            PhysPointerError::NoMappingInfo => OpteeSmcReturnCode::ENomem,
            _ => OpteeSmcReturnCode::EBadAddr,
        }
    }
}

impl From<OpteeSmcReturnCode> for litebox_common_linux::errno::Errno {
    fn from(ret: OpteeSmcReturnCode) -> Self {
        match ret {
            OpteeSmcReturnCode::EBusy | OpteeSmcReturnCode::EThreadLimit => {
                litebox_common_linux::errno::Errno::EBUSY
            }
            OpteeSmcReturnCode::EResume => litebox_common_linux::errno::Errno::EAGAIN,
            OpteeSmcReturnCode::EBadAddr => litebox_common_linux::errno::Errno::EFAULT,
            OpteeSmcReturnCode::ENomem => litebox_common_linux::errno::Errno::ENOMEM,
            OpteeSmcReturnCode::ENotAvail => litebox_common_linux::errno::Errno::ENOENT,
            _ => litebox_common_linux::errno::Errno::EINVAL,
        }
    }
}

/// Parse the `.ta_head` section from a raw ELF binary.
///
/// This function searches for the `.ta_head` section in the ELF and parses the `TaHead`
/// structure from it. Returns `None` if the section is not found or cannot be parsed.
///
/// # Arguments
/// * `elf_data` - Raw bytes of the ELF binary
pub fn parse_ta_head(elf_data: &[u8]) -> Option<TaHead> {
    use core::mem::size_of;
    use elf::{ElfBytes, endian::AnyEndian};

    let elf = ElfBytes::<AnyEndian>::minimal_parse(elf_data).ok()?;
    let (shdrs, strtab) = elf.section_headers_with_strtab().ok()?;
    let shdrs = shdrs?;
    let strtab = strtab?;

    for shdr in shdrs {
        let name = strtab.get(shdr.sh_name as usize).ok()?;
        if name == TA_HEAD_SECTION_NAME {
            let offset: usize = shdr.sh_offset.truncate();
            let size: usize = shdr.sh_size.truncate();

            if size < size_of::<TaHead>() {
                return None;
            }

            return TaHead::read_from_bytes(&elf_data[offset..offset + size_of::<TaHead>()]).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tee_uuid_from_u64_array() {
        // Test with OP-TEE's well-known UUID: 384fb3e0-e7f8-11e3-af63-0002a5d5c51b
        // UUID bytes (big-endian for time fields):
        // [0x38, 0x4f, 0xb3, 0xe0, 0xe7, 0xf8, 0x11, 0xe3, 0xaf, 0x63, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b]
        // When read as two little-endian u64 values:
        // data[0] = bytes[0..8] as LE u64 = 0xe311f8e7_e0b34f38
        // data[1] = bytes[8..16] as LE u64 = 0x1bc5d5a5_020063af
        let uuid = TeeUuid::from_u64_array([0xe311f8e7_e0b34f38, 0x1bc5d5a5_020063af]);

        assert_eq!(uuid.time_low, 0x384fb3e0);
        assert_eq!(uuid.time_mid, 0xe7f8);
        assert_eq!(uuid.time_hi_and_version, 0x11e3);
        assert_eq!(
            uuid.clock_seq_and_node,
            [0xaf, 0x63, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b]
        );
    }
}

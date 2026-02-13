// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common elements to enable OP-TEE-like functionalities

#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use core::mem::size_of;
use litebox::platform::RawConstPointer as _;
use litebox::utils::TruncateExt;
use litebox_common_linux::{PtRegs, errno::Errno};
use num_enum::TryFromPrimitive;
use syscall_nr::{LdelfSyscallNr, TeeSyscallNr};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

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

/// Number of TEE parameters to be passed to TAs.
const TEE_NUM_PARAMS: usize = 4;

/// Number of RPC parameters that LiteBox defined and reported to the normal-world
/// Linux kernel driver during `EXCHANGE_CAPABILITIES`. The Linux kernel driver is
/// expected to allocate a shared buffer for this number of parameters.
pub const NUM_RPC_PARAMS: usize = 4;

/// Packed parameter types for [`UteeParams`].
///
/// Wire layout (little-endian u64):
/// - bits \[3:0\]   – type_0
/// - bits \[7:4\]   – type_1
/// - bits \[11:8\]  – type_2
/// - bits \[15:12\] – type_3
/// - bits \[63:16\] – reserved (zero)
#[derive(Clone, Copy, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(transparent)]
pub struct UteeParamsTypes(u64);

impl UteeParamsTypes {
    const NIBBLE_MASK: u64 = 0xF;

    /// Get the 4-bit type at the given `index` (0–3).
    #[allow(clippy::cast_possible_truncation)]
    fn get(self, index: usize) -> u8 {
        ((self.0 >> (index * 4)) & Self::NIBBLE_MASK) as u8
    }

    /// Set the 4-bit type at the given `index` (0–3).
    fn set(&mut self, index: usize, value: u8) {
        let shift = index * 4;
        self.0 = (self.0 & !(Self::NIBBLE_MASK << shift)) | (u64::from(value & 0xF) << shift);
    }

    pub fn type_0(&self) -> u8 {
        self.get(0)
    }
    pub fn type_1(&self) -> u8 {
        self.get(1)
    }
    pub fn type_2(&self) -> u8 {
        self.get(2)
    }
    pub fn type_3(&self) -> u8 {
        self.get(3)
    }
    pub fn set_type_0(&mut self, v: u8) {
        self.set(0, v);
    }
    pub fn set_type_1(&mut self, v: u8) {
        self.set(1, v);
    }
    pub fn set_type_2(&mut self, v: u8) {
        self.set(2, v);
    }
    pub fn set_type_3(&mut self, v: u8) {
        self.set(3, v);
    }
}

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

// RPC command IDs from `optee_os/core/include/optee_msg.h`.
// These occupy the `cmd` field of the RPC `optee_msg_arg`, which is a separate namespace
// from `OPTEE_MSG_CMD_*` used for main messaging.
const OPTEE_MSG_RPC_CMD_LOAD_TA: u32 = 0;
const OPTEE_MSG_RPC_CMD_RPMB: u32 = 1;
const OPTEE_MSG_RPC_CMD_FS: u32 = 2;
const OPTEE_MSG_RPC_CMD_GET_TIME: u32 = 3;
const OPTEE_MSG_RPC_CMD_WAIT_QUEUE: u32 = 4;
const OPTEE_MSG_RPC_CMD_SUSPEND: u32 = 5;
const OPTEE_MSG_RPC_CMD_SHM_ALLOC: u32 = 28;
const OPTEE_MSG_RPC_CMD_SHM_FREE: u32 = 29;
const OPTEE_MSG_RPC_CMD_NOTIFICATION: u32 = 30;

/// `OPTEE_MSG_RPC_CMD_*` from `optee_os/core/include/optee_msg.h`
///
/// These are the command IDs used in the `cmd` field of the RPC `optee_msg_arg`.
/// They live in a separate namespace from [`OpteeMessageCommand`] (which is for main
/// messaging between the normal-world driver and OP-TEE OS).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum OpteeRpcCommand {
    /// Load a Trusted Application binary.
    LoadTa = OPTEE_MSG_RPC_CMD_LOAD_TA,
    /// Replay Protected Memory Block (RPMB) access.
    Rpmb = OPTEE_MSG_RPC_CMD_RPMB,
    /// REE file-system access.
    Fs = OPTEE_MSG_RPC_CMD_FS,
    /// Get REE time.
    GetTime = OPTEE_MSG_RPC_CMD_GET_TIME,
    /// Wait-queue sleep/wake.
    WaitQueue = OPTEE_MSG_RPC_CMD_WAIT_QUEUE,
    /// Suspend execution.
    Suspend = OPTEE_MSG_RPC_CMD_SUSPEND,
    /// Allocate shared memory for RPC output.
    ShmAlloc = OPTEE_MSG_RPC_CMD_SHM_ALLOC,
    /// Free previously allocated shared memory.
    ShmFree = OPTEE_MSG_RPC_CMD_SHM_FREE,
    /// Asynchronous notification.
    Notification = OPTEE_MSG_RPC_CMD_NOTIFICATION,
}

/// Temporary memory reference parameter
///
/// `optee_msg_param_tmem` from `optee_os/core/include/optee_msg.h`
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
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
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
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
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
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
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct OpteeMsgParamValue {
    pub a: u64,
    pub b: u64,
    pub c: u64,
}

/// Parameter used together with `OpteeMsgArgs`.
///
/// The 24-byte `data` field is the on-wire union of [`OpteeMsgParamTmem`],
/// [`OpteeMsgParamRmem`], [`OpteeMsgParamFmem`], and [`OpteeMsgParamValue`].
/// Use the typed accessor methods to interpret it.
const OPTEE_MSG_PARAM_DATA_SIZE: usize = 24;

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

/// Attribute field of [`OpteeMsgParam`].
///
/// Wire layout (little-endian u64):
/// - bits \[7:0\]  – type (`OPTEE_MSG_ATTR_TYPE_*`)
/// - bit  8       – meta
/// - bit  9       – noncontig
/// - bits \[63:10\] – reserved (zero)
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct OpteeMsgAttr(u64);

impl OpteeMsgAttr {
    /// Returns the attribute type (bits 0–7).
    #[allow(clippy::cast_possible_truncation)]
    pub fn typ(&self) -> u8 {
        self.0 as u8
    }

    /// Returns `true` when the meta bit (bit 8) is set.
    pub fn meta(&self) -> bool {
        self.0 & (1 << 8) != 0
    }

    /// Returns `true` when the noncontig bit (bit 9) is set.
    pub fn noncontig(&self) -> bool {
        self.0 & (1 << 9) != 0
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct OpteeMsgParam {
    attr: OpteeMsgAttr,
    data: [u8; OPTEE_MSG_PARAM_DATA_SIZE],
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
            OpteeMsgParamTmem::read_from_bytes(&self.data).ok()
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
            OpteeMsgParamRmem::read_from_bytes(&self.data).ok()
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
            OpteeMsgParamFmem::read_from_bytes(&self.data).ok()
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
            OpteeMsgParamValue::read_from_bytes(&self.data).ok()
        } else {
            None
        }
    }
}

/// Compute the total byte size of an `optee_msg_arg` with `num_params` parameters.
/// Equivalent to the C macro `OPTEE_MSG_GET_ARG_SIZE(num_params)`.
///
/// Returns `size_of::<OpteeMsgArgsHeader>() + num_params * size_of::<OpteeMsgParam>()`
/// (i.e. the 32-byte header plus N × 32-byte parameter slots).
///
/// `num_params` is the total count of entries in `params[]`, which includes both meta
/// parameters and client parameters. For example, `OpenSession` uses `TEE_NUM_PARAMS + 2`
/// (4 client + 2 meta) and `InvokeCommand` uses up to `TEE_NUM_PARAMS` (4 client).
///
/// # Safety invariant
///
/// Callers must ensure `num_params` has been validated against `OpteeMsgArgs::MAX_PARAMS`.
/// An unvalidated `num_params` from normal world memory could produce an oversized result,
/// leading to out-of-bounds access on fixed-size arrays.
/// See CVE-2022-46152 (OP-TEE OOB via unvalidated `num_params`).
pub const fn optee_msg_arg_total_size(num_params: u32) -> usize {
    debug_assert!(
        num_params as usize <= OpteeMsgArgs::MAX_PARAMS,
        "optee_msg_arg_total_size: num_params exceeds MAX_PARAMS"
    );
    core::mem::size_of::<OpteeMsgArgsHeader>()
        + core::mem::size_of::<OpteeMsgParam>() * num_params as usize
}

/// Zerocopy-friendly header of `optee_msg_arg`.
///
/// This struct represents the fixed 32-byte header of the C `struct optee_msg_arg`.
/// Unlike `OpteeMsgArgs`, all fields are plain `u32` so it can derive `FromBytes`/`IntoBytes`.
///
/// A single `optee_msg_arg` on the wire:
///
/// ```text
/// byte offset
/// 0             cmd        (u32)
/// 4             func       (u32)
/// 8             session    (u32)
/// 12            cancel_id  (u32)
/// 16            pad        (u32)
/// 20            ret        (u32)
/// 24            ret_origin (u32)
/// 28            num_params (u32)   N = num_params
///               ---- header: 32 bytes (OpteeMsgArgsHeader) ----
/// 32            params[0]  (32 bytes each, OpteeMsgParam)
/// 64            params[1]
///               ...
/// 32 + N*32     (end)
/// ```
///
/// Total size = `size_of::<OpteeMsgArgsHeader>() + N * size_of::<OpteeMsgParam>()`
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct OpteeMsgArgsHeader {
    pub cmd: u32,
    pub func: u32,
    pub session: u32,
    pub cancel_id: u32,
    pub pad: u32,
    pub ret: u32,
    pub ret_origin: u32,
    pub num_params: u32,
}

/// `optee_msg_arg` from `optee_os/core/include/optee_msg.h`
/// OP-TEE message argument structure that the normal world (or VTL0) OP-TEE driver and OP-TEE OS use to
/// exchange messages. This data structure is used for carrying RPC information as well.
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
    /// Number of parameters contained in `params`.
    ///
    /// For main args: includes both meta parameters (e.g. TA UUID, client identity for
    /// `OpenSession`) and client parameters. Typical values: 0 (close/cancel),
    /// `TEE_NUM_PARAMS` (invoke), `TEE_NUM_PARAMS + 2` (open_session).
    /// For RPC args: the count negotiated during `EXCHANGE_CAPABILITIES`.
    pub num_params: u32,
    /// Parameters to be passed to/from the secure world. If `cmd == OpenSession`, the first
    /// two params are meta parameters (TA UUID and client identity, marked with
    /// `OPTEE_MSG_ATTR_META`) and are not delivered to the TA.
    ///
    /// The C `struct optee_msg_arg` uses a flexible array member `params[]` whose length
    /// is determined by `num_params`. We fix it to `TEE_NUM_PARAMS + 2` (= `MAX_PARAMS`)
    /// to match the Linux driver's `MAX_ARG_PARAM_COUNT`. The variable-length wire format
    /// is handled by the read/write proxy in `msg_handler.rs` and `write_msg_args_to_normal_world`.
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
            self.params[index].data.copy_from_slice(value.as_bytes());
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
            // rmem.size and tmem.size are at byte offset 8 in the 24-byte data,
            // the same position as value.b in the original union.
            self.params[index].data[8..16].copy_from_slice(&size.to_le_bytes());
            Ok(())
        }
    }

    /// Maximum number of parameters that `OpteeMsgArgs` can hold.
    ///
    /// This is `TEE_NUM_PARAMS + 2` = 6, matching the Linux driver's `MAX_ARG_PARAM_COUNT`.
    /// The `+2` accounts for the meta parameters (TA UUID + client identity) that the
    /// Linux driver prepends for `OpenSession` commands. For `InvokeCommand`, only
    /// `TEE_NUM_PARAMS` (4) client parameters are used. For RPC args, the actual
    /// `num_params` is negotiated during `EXCHANGE_CAPABILITIES` (typically 1-2 in
    /// upstream OP-TEE), but we cap it to this same array size.
    pub const MAX_PARAMS: usize = TEE_NUM_PARAMS + 2;

    /// Construct an `OpteeMsgArgs` from a zerocopy header and a raw parameter byte slice.
    ///
    /// `raw_params` must contain at least `header.num_params * size_of::<OpteeMsgParam>()` bytes.
    /// `header.num_params` must not exceed `MAX_PARAMS` (6). Note that `num_params` counts
    /// **all** entries in the `params[]` array, including meta parameters — e.g. for
    /// `OpenSession`, the Linux driver sets `num_params = TEE_NUM_PARAMS + 2` (4 client
    /// params + 2 meta params for TA UUID and client identity). For RPC args, `num_params`
    /// is the count negotiated during `EXCHANGE_CAPABILITIES`.
    ///
    /// This bounds check is critical defense-in-depth against CVE-2022-46152-style attacks
    /// where an unvalidated `num_params` from normal world causes OOB access on fixed arrays.
    pub fn from_header_and_raw_params(
        header: &OpteeMsgArgsHeader,
        raw_params: &[u8],
    ) -> Result<Self, OpteeSmcReturnCode> {
        let num = header.num_params as usize;
        if num > Self::MAX_PARAMS {
            return Err(OpteeSmcReturnCode::EBadCmd);
        }
        let needed = num * size_of::<OpteeMsgParam>();
        if raw_params.len() < needed {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }

        let cmd =
            OpteeMessageCommand::try_from(header.cmd).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

        let ret = TeeResult::try_from(header.ret).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

        let ret_origin = TeeOrigin::read_from_bytes(header.ret_origin.as_bytes())
            .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

        let mut params = [OpteeMsgParam {
            attr: OpteeMsgAttr::default(),
            data: [0u8; OPTEE_MSG_PARAM_DATA_SIZE],
        }; Self::MAX_PARAMS];

        for (i, param) in params.iter_mut().enumerate().take(num) {
            let offset = i * size_of::<OpteeMsgParam>();
            let param_bytes = &raw_params[offset..offset + size_of::<OpteeMsgParam>()];
            *param = OpteeMsgParam::read_from_bytes(param_bytes)
                .map_err(|_| OpteeSmcReturnCode::EBadAddr)?;
        }

        Ok(Self {
            cmd,
            func: header.func,
            session: header.session,
            cancel_id: header.cancel_id,
            pad: header.pad,
            ret,
            ret_origin,
            num_params: header.num_params,
            params,
        })
    }

    /// Convert the header portion of this `OpteeMsgArgs` back to an `OpteeMsgArgsHeader`.
    pub fn to_header(&self) -> OpteeMsgArgsHeader {
        OpteeMsgArgsHeader {
            cmd: self.cmd as u32,
            func: self.func,
            session: self.session,
            cancel_id: self.cancel_id,
            pad: self.pad,
            ret: self.ret as u32,
            ret_origin: *self.ret_origin.value(),
            num_params: self.num_params,
        }
    }

    /// Serialize the params portion (up to `num_params`) as raw bytes into `buf`.
    ///
    /// Re-validates `num_params <= MAX_PARAMS` before using as loop bound.
    /// See CVE-2022-46152 for why this defense-in-depth matters.
    pub fn write_raw_params(&self, buf: &mut [u8]) -> Result<usize, OpteeSmcReturnCode> {
        let num = self.num_params as usize;
        if num > Self::MAX_PARAMS {
            return Err(OpteeSmcReturnCode::EBadCmd);
        }
        let needed = num * size_of::<OpteeMsgParam>();
        if buf.len() < needed {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }
        for i in 0..num {
            let offset = i * size_of::<OpteeMsgParam>();
            buf[offset..offset + size_of::<OpteeMsgParam>()]
                .copy_from_slice(self.params[i].as_bytes());
        }
        Ok(needed)
    }
}

/// OP-TEE RPC argument structure.
///
/// This is the RPC counterpart of [`OpteeMsgArgs`]. On the wire it shares the same
/// 32-byte header layout (`optee_msg_arg`), but only a subset of the header fields
/// are meaningful for RPC:
///
/// | Field                | RPC meaning                                                |
/// |----------------------|------------------------------------------------------------|
/// | `cmd`                | RPC command ([`OpteeRpcCommand`])                          |
/// | `ret` / `ret_origin` | Return value written back by the normal-world RPC handler. |
/// | `num_params`         | Number of RPC parameters (`EXCHANGE_CAPABILITIES`).        |
/// | `params[]`           | RPC payload (e.g. TA load request).                        |
///
/// The remaining header fields (`func`, `session`, `cancel_id`) are **unused** for RPC
/// and always zero on the wire. They are not exposed in this struct.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct OpteeRpcArgs {
    /// RPC command ID. Unlike main args, this uses [`OpteeRpcCommand`] (e.g. `LoadTa`,
    /// `ShmAlloc`) rather than [`OpteeMessageCommand`].
    pub cmd: OpteeRpcCommand,
    /// unused for RPC. Corresponds to `func` in the main `optee_msg_arg`.
    _reserved_func: u32,
    /// unused for RPC. Corresponds to `session`.
    _reserved_session: u32,
    /// unused for RPC. Corresponds to `cancel_id`.
    _reserved_cancel_id: u32,
    /// Padding (matches `pad` in the wire format).
    _pad: u32,
    /// Return value from the normal-world RPC handler.
    pub ret: TeeResult,
    /// Origin of the return value.
    pub ret_origin: TeeOrigin,
    /// Number of parameters in `params`, negotiated during `EXCHANGE_CAPABILITIES`.
    pub num_params: u32,
    /// RPC parameters. Fixed to [`NUM_RPC_PARAMS`] entries.
    pub params: [OpteeMsgParam; Self::MAX_PARAMS],
}

impl OpteeRpcArgs {
    /// Maximum number of RPC parameters this struct can hold.
    ///
    /// This is [`NUM_RPC_PARAMS`], the count negotiated during `EXCHANGE_CAPABILITIES`.
    pub const MAX_PARAMS: usize = NUM_RPC_PARAMS;

    /// Construct an `OpteeRpcArgs` from a zerocopy header and a raw parameter byte slice.
    ///
    /// The `cmd` field is parsed as [`OpteeRpcCommand`]. Unlike
    /// [`OpteeMsgArgs::from_header_and_raw_params`], `func`, `session`, and `cancel_id`
    /// are stored as reserved zeros — they carry no meaning for RPC.
    pub fn from_header_and_raw_params(
        header: &OpteeMsgArgsHeader,
        raw_params: &[u8],
    ) -> Result<Self, OpteeSmcReturnCode> {
        let num = header.num_params as usize;
        if num > Self::MAX_PARAMS {
            return Err(OpteeSmcReturnCode::EBadCmd);
        }
        let needed = num * size_of::<OpteeMsgParam>();
        if raw_params.len() < needed {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }

        let cmd = OpteeRpcCommand::try_from(header.cmd).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

        let ret = TeeResult::try_from(header.ret).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

        let ret_origin = TeeOrigin::read_from_bytes(header.ret_origin.as_bytes())
            .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

        let mut params = [OpteeMsgParam {
            attr: OpteeMsgAttr::default(),
            data: [0u8; OPTEE_MSG_PARAM_DATA_SIZE],
        }; Self::MAX_PARAMS];

        for (i, param) in params.iter_mut().enumerate().take(num) {
            let offset = i * size_of::<OpteeMsgParam>();
            let param_bytes = &raw_params[offset..offset + size_of::<OpteeMsgParam>()];
            *param = OpteeMsgParam::read_from_bytes(param_bytes)
                .map_err(|_| OpteeSmcReturnCode::EBadAddr)?;
        }

        Ok(Self {
            cmd,
            _reserved_func: 0,
            _reserved_session: 0,
            _reserved_cancel_id: 0,
            _pad: 0,
            ret,
            ret_origin,
            num_params: header.num_params,
            params,
        })
    }

    /// Convert back to an [`OpteeMsgArgsHeader`] for wire serialization.
    ///
    /// The reserved fields (`func`, `session`, `cancel_id`) are written as 0.
    pub fn to_header(&self) -> OpteeMsgArgsHeader {
        OpteeMsgArgsHeader {
            cmd: self.cmd as u32,
            func: 0,
            session: 0,
            cancel_id: 0,
            pad: 0,
            ret: self.ret as u32,
            ret_origin: *self.ret_origin.value(),
            num_params: self.num_params,
        }
    }

    /// Serialize the params portion (up to `num_params`) as raw bytes into `buf`.
    pub fn write_raw_params(&self, buf: &mut [u8]) -> Result<usize, OpteeSmcReturnCode> {
        let num = self.num_params as usize;
        if num > Self::MAX_PARAMS {
            return Err(OpteeSmcReturnCode::EBadCmd);
        }
        let needed = num * size_of::<OpteeMsgParam>();
        if buf.len() < needed {
            return Err(OpteeSmcReturnCode::EBadAddr);
        }
        for i in 0..num {
            let offset = i * size_of::<OpteeMsgParam>();
            buf[offset..offset + size_of::<OpteeMsgParam>()]
                .copy_from_slice(self.params[i].as_bytes());
        }
        Ok(needed)
    }

    /// Access a parameter by index with bounds checking against `num_params`.
    pub fn get_param_value(&self, index: usize) -> Result<OpteeMsgParamValue, OpteeSmcReturnCode> {
        if index >= self.num_params as usize {
            Err(OpteeSmcReturnCode::ENotAvail)
        } else {
            self.params[index]
                .get_param_value()
                .ok_or(OpteeSmcReturnCode::EBadCmd)
        }
    }

    /// Access a tmem parameter by index with bounds checking against `num_params`.
    pub fn get_param_tmem(&self, index: usize) -> Result<OpteeMsgParamTmem, OpteeSmcReturnCode> {
        if index >= self.num_params as usize {
            Err(OpteeSmcReturnCode::ENotAvail)
        } else {
            self.params[index]
                .get_param_tmem()
                .ok_or(OpteeSmcReturnCode::EBadCmd)
        }
    }
    // Note: RPC does not use rmem params. Rmem requires pre-registered shared memory
    // references from the normal-world driver, which is a main-messaging-path concept.
    // RPC uses tmem for buffer references since OP-TEE provides physical addresses directly.
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
        rpc_args: Option<Box<OpteeRpcArgs>>,
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
#[derive(Copy, Clone, Debug, PartialEq, TryFromPrimitive)]
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
    fn test_optee_msg_args_header_size_and_layout() {
        use core::mem::{offset_of, size_of};
        assert_eq!(size_of::<OpteeMsgArgsHeader>(), 32);
        assert_eq!(offset_of!(OpteeMsgArgsHeader, cmd), 0);
        assert_eq!(offset_of!(OpteeMsgArgsHeader, func), 4);
        assert_eq!(offset_of!(OpteeMsgArgsHeader, session), 8);
        assert_eq!(offset_of!(OpteeMsgArgsHeader, cancel_id), 12);
        assert_eq!(offset_of!(OpteeMsgArgsHeader, pad), 16);
        assert_eq!(offset_of!(OpteeMsgArgsHeader, ret), 20);
        assert_eq!(offset_of!(OpteeMsgArgsHeader, ret_origin), 24);
        assert_eq!(offset_of!(OpteeMsgArgsHeader, num_params), 28);
    }

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

    #[test]
    fn test_header_to_msg_args_too_many_params() {
        let header = OpteeMsgArgsHeader {
            cmd: 0,
            func: 0,
            session: 0,
            cancel_id: 0,
            pad: 0,
            ret: 0,
            ret_origin: 0,
            num_params: 7, // exceeds MAX_PARAMS = 6
        };
        let result = OpteeMsgArgs::from_header_and_raw_params(&header, &[0u8; 224]);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_to_msg_args_raw_params_too_short() {
        let header = OpteeMsgArgsHeader {
            cmd: 0,
            func: 0,
            session: 0,
            cancel_id: 0,
            pad: 0,
            ret: 0,
            ret_origin: 0,
            num_params: 4,
        };
        let result = OpteeMsgArgs::from_header_and_raw_params(&header, &[0u8; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip_header_params_write_read() {
        use alloc::vec;

        let header = OpteeMsgArgsHeader {
            cmd: 1, // InvokeCommand
            func: 0x1234,
            session: 0xABCD,
            cancel_id: 0,
            pad: 0,
            ret: 0,
            ret_origin: 0,
            num_params: 3,
        };
        let mut params_in = vec![0u8; 3 * size_of::<OpteeMsgParam>()];
        for (i, byte) in params_in.iter_mut().enumerate() {
            *byte = u8::try_from(i % 256).unwrap();
        }

        let msg_args =
            OpteeMsgArgs::from_header_and_raw_params(&header, &params_in).expect("expected Ok");
        assert_eq!(msg_args.func, 0x1234);
        assert_eq!(msg_args.session, 0xABCD);
        assert_eq!(msg_args.num_params, 3);

        let header_out = msg_args.to_header();
        assert_eq!(header_out.cmd, 1);
        assert_eq!(header_out.func, 0x1234);
        assert_eq!(header_out.session, 0xABCD);
        assert_eq!(header_out.num_params, 3);

        let mut params_out = vec![0u8; 3 * size_of::<OpteeMsgParam>()];
        let written = msg_args
            .write_raw_params(&mut params_out)
            .expect("expected Ok");
        assert_eq!(written, 3 * size_of::<OpteeMsgParam>());
        assert_eq!(&params_out[..written], &params_in[..written]);
    }

    #[test]
    fn test_zero_params() {
        let header = OpteeMsgArgsHeader {
            cmd: 3, // Cancel
            func: 0,
            session: 1,
            cancel_id: 42,
            pad: 0,
            ret: 0,
            ret_origin: 0,
            num_params: 0,
        };
        let msg_args = OpteeMsgArgs::from_header_and_raw_params(&header, &[]).expect("expected Ok");
        assert_eq!(msg_args.num_params, 0);
        assert_eq!(msg_args.cancel_id, 42);

        let header_out = msg_args.to_header();
        assert_eq!(header_out.num_params, 0);

        let mut buf = [0u8; 0];
        let written = msg_args.write_raw_params(&mut buf).expect("expected Ok");
        assert_eq!(written, 0);
    }

    #[test]
    fn test_max_params() {
        use alloc::vec;

        let header = OpteeMsgArgsHeader {
            cmd: 0, // OpenSession
            func: 0,
            session: 0,
            cancel_id: 0,
            pad: 0,
            ret: 0,
            ret_origin: 0,
            num_params: 6, // MAX_PARAMS
        };
        let params = vec![0xABu8; 6 * size_of::<OpteeMsgParam>()];
        let msg_args =
            OpteeMsgArgs::from_header_and_raw_params(&header, &params).expect("expected Ok");
        assert_eq!(msg_args.num_params, 6);

        let mut params_out = vec![0u8; 6 * size_of::<OpteeMsgParam>()];
        let written = msg_args
            .write_raw_params(&mut params_out)
            .expect("expected Ok");
        assert_eq!(written, 6 * size_of::<OpteeMsgParam>());
        assert_eq!(params_out, params);
    }

    #[test]
    fn test_optee_rpc_args_roundtrip() {
        use alloc::vec;

        // ShmAlloc = 28
        let header = OpteeMsgArgsHeader {
            cmd: 28,
            func: 0,
            session: 0,
            cancel_id: 0,
            pad: 0,
            ret: 0,
            ret_origin: 0,
            num_params: 2,
        };
        let mut params_in = vec![0u8; 2 * size_of::<OpteeMsgParam>()];
        for (i, byte) in params_in.iter_mut().enumerate() {
            *byte = u8::try_from(i % 256).unwrap();
        }

        let rpc_args = OpteeRpcArgs::from_header_and_raw_params(&header, &params_in)
            .expect("should parse RPC args");
        assert_eq!(rpc_args.cmd, OpteeRpcCommand::ShmAlloc);
        assert_eq!(rpc_args.num_params, 2);

        let header_out = rpc_args.to_header();
        assert_eq!(header_out.cmd, 28);
        assert_eq!(header_out.func, 0);
        assert_eq!(header_out.session, 0);
        assert_eq!(header_out.cancel_id, 0);
        assert_eq!(header_out.num_params, 2);

        let mut params_out = vec![0u8; 2 * size_of::<OpteeMsgParam>()];
        let written = rpc_args
            .write_raw_params(&mut params_out)
            .expect("should serialize");
        assert_eq!(written, 2 * size_of::<OpteeMsgParam>());
        assert_eq!(&params_out[..written], &params_in[..written]);
    }

    #[test]
    fn test_rpc_args_rejects_main_cmd() {
        // OpenSession = 0 is a main command, but also happens to be LoadTa = 0 for RPC.
        // InvokeCommand = 1 maps to Rpmb = 1 in RPC. So to test rejection we need a
        // cmd value that's valid for main but not for RPC. RegisterShm = 4 has no
        // RPC counterpart.
        let header = OpteeMsgArgsHeader {
            cmd: 4, // RegisterShm — not a valid OpteeRpcCommand
            func: 0,
            session: 0,
            cancel_id: 0,
            pad: 0,
            ret: 0,
            ret_origin: 0,
            num_params: 0,
        };
        assert!(OpteeRpcArgs::from_header_and_raw_params(&header, &[]).is_err());
    }

    #[test]
    fn test_rpc_args_reserved_fields_zeroed() {
        let header = OpteeMsgArgsHeader {
            cmd: 29, // ShmFree
            func: 0xDEAD,
            session: 0xBEEF,
            cancel_id: 0xCAFE,
            pad: 0,
            ret: 0,
            ret_origin: 0,
            num_params: 0,
        };
        let rpc_args =
            OpteeRpcArgs::from_header_and_raw_params(&header, &[]).expect("should parse");
        assert_eq!(rpc_args.cmd, OpteeRpcCommand::ShmFree);

        // Reserved fields should be zeroed regardless of header input
        let hdr_out = rpc_args.to_header();
        assert_eq!(hdr_out.func, 0);
        assert_eq!(hdr_out.session, 0);
        assert_eq!(hdr_out.cancel_id, 0);
    }
}

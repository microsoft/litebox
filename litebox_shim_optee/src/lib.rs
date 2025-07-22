//! A shim that provides an OP-TEE-compatible ABI via LiteBox

#![no_std]

extern crate alloc;

use alloc::vec;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_linux::errno::Errno;
use litebox_platform_multiplex::Platform;
use syscalls::syscall_nr::TeeSyscallNr;

pub(crate) mod syscalls;

const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

/// Handle OP-TEE syscalls
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development purposes.
pub fn handle_syscall_request(request: SyscallRequest<Platform>) -> isize {
    let res: Result<usize, Errno> = match request {
        SyscallRequest::Return { ret } => syscalls::tee::sys_return(ret),
        SyscallRequest::Log { buf, len } => match unsafe { buf.to_cow_slice(len) } {
            Some(buf) => syscalls::tee::sys_log(&buf),
            None => Err(Errno::EFAULT),
        },
        SyscallRequest::Panic { code } => syscalls::tee::sys_panic(code),
        SyscallRequest::CrypRandomNumberGenerate { buf, blen } => {
            let mut kernel_buf = vec![0u8; blen.min(MAX_KERNEL_BUF_SIZE)];
            syscalls::cryp::sys_cryp_random_number_generate(&mut kernel_buf).and_then(|()| {
                buf.copy_from_slice(0, &kernel_buf)
                    .map(|()| 0)
                    .ok_or(Errno::EFAULT)
            })
        }
        _ => todo!(),
    };

    res.map_or_else(
        |e| {
            let e: i32 = e.as_neg();
            let Ok(e) = isize::try_from(e) else {
                // On both 32-bit and 64-bit, this should never be triggered
                unreachable!()
            };
            e
        },
        |val: usize| {
            let Ok(v) = isize::try_from(val) else {
                // Note in case where val is an address (e.g., returned from `mmap`), we currently
                // assume user space address does not exceed isize::MAX. On 64-bit, the max user
                // address is 0x7FFF_FFFF_F000, which is below this; for 32-bit, this may not hold,
                // and we might need to de-restrict this if ever seen in practice. For now, we are
                // keeping the stricter version.
                unreachable!("invalid user pointer");
            };
            v
        },
    )
}

// From`optee_os/lib/libutee/include/utee_syscalls.h`
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
    OpenTaSession {
        ta_uuid: Platform::RawConstPointer<TeeUuid>,
        cancel_req_to: u32,
        usr_params: Platform::RawConstPointer<UteeParams>,
        ta_sess_id: Platform::RawMutPointer<u32>,
        ret_orig: Platform::RawMutPointer<u32>,
    },
    CloseTaSession {
        ta_sess_id: Platform::RawMutPointer<u32>,
    },
    InvokeTaCommand {
        ta_sess_id: u32,
        cancel_req_to: u32,
        cmd_id: u32,
        params: Platform::RawConstPointer<UteeParams>,
        ret_orig: Platform::RawMutPointer<u32>,
    },
    CheckAccessRights {
        flags: u32,
        buf: Platform::RawConstPointer<u8>,
        len: usize,
    },
    CrypStateAlloc {
        algo: usize,
        op_mode: TeeOperationMode,
        key1: usize,
        key2: usize,
        state_id: Platform::RawMutPointer<u32>,
    },
    CrypStateCopy {
        dst_state_id: u32,
        src_state_id: u32,
    },
    CrypStateFree {
        state_id: u32,
    },
    CipherInit {
        state_id: u32,
        iv: Platform::RawConstPointer<u8>,
        iv_len: usize,
    },
    CipherUpdate {
        state_id: u32,
        src: Platform::RawConstPointer<u8>,
        src_len: usize,
        dst: Platform::RawMutPointer<u8>,
        dst_len: Platform::RawMutPointer<u64>,
    },
    CipherFinal {
        state_id: u32,
        src: Platform::RawConstPointer<u8>,
        src_len: usize,
        dst: Platform::RawMutPointer<u8>,
        dst_len: Platform::RawMutPointer<u64>,
    },
    CrypObjGetInfo {
        obj_id: u32,
        info: Platform::RawMutPointer<TeeObjectInfo>,
    },
    CrypObjAlloc {
        obj_type: u32,
        max_key_size: usize,
        obj_id: Platform::RawMutPointer<u32>,
    },
    CrypObjClose {
        obj_id: u32,
    },
    CrypObjReset {
        obj_id: u32,
    },
    CrypObjPopulate {
        obj_id: u32,
        usr_attrs: Platform::RawMutPointer<UteeAttribute>,
        attr_count: usize,
    },
    CrypObjCopy {
        dst_obj_id: u32,
        src_obj_id: u32,
    },
    CrypRandomNumberGenerate {
        buf: Platform::RawMutPointer<u8>,
        blen: usize,
    },
}

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
            TeeSyscallNr::Unknown => {
                return Err(Errno::ENOSYS);
            }
            _ => todo!(),
        };

        Ok(dispatcher)
    }
}

// a subset of `SyscallContext` for shim's operation
#[derive(Clone, Copy, Debug)]
#[repr(C)]
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
}

const TEE_NUM_PARAMS: usize = 4;

// `utee_params` from `optee_os/lib/libutee/include/utee_types.h`
#[derive(PartialEq, Default, Clone, Copy)]
#[repr(C)]
pub struct UteeParams {
    pub types: u64,
    pub vals: [u64; TEE_NUM_PARAMS * 2],
}

// `utee_attribute` from `optee_os/lib/libutee/include/utee_types.h`
#[derive(PartialEq, Default, Clone, Copy)]
#[repr(C)]
pub struct UteeAttribute {
    pub a: u64,
    pub b: u64,
    pub attribute_id: u32,
}

// `TEE_UUID` from `optee_os/lib/libutee/include/tee_api_types.h`
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TeeUuid {
    time_low: u32,
    time_mid: u16,
    time_hi_and_version: u16,
    clock_seq_and_node: [u8; 8],
}

// `TEE_ObjectInfo` from `optee_os/lib/libutee/include/tee_api_types.h`
// assume 1.1.1 spec
#[derive(PartialEq, Default, Clone, Copy)]
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

const TEE_MODE_ENCRYPT: usize = 0;
const TEE_MODE_DECRYPT: usize = 1;
const TEE_MODE_SIGN: usize = 2;
const TEE_MODE_VERIFY: usize = 3;
const TEE_MODE_MAC: usize = 4;
const TEE_MODE_DIGEST: usize = 5;
const TEE_MODE_DERIVE: usize = 6;

#[derive(Debug, PartialEq)]
#[repr(usize)]
pub enum TeeOperationMode {
    Encrypt = TEE_MODE_ENCRYPT,
    Decrypt = TEE_MODE_DECRYPT,
    Sign = TEE_MODE_SIGN,
    Verify = TEE_MODE_VERIFY,
    Mac = TEE_MODE_MAC,
    Digest = TEE_MODE_DIGEST,
    Derive = TEE_MODE_DERIVE,
}

//! A shim that provides an OP-TEE-compatible ABI via LiteBox

#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

// TODO(jayb) Replace out all uses of once_cell and such with our own implementation that uses
// platform-specific things within it.
use once_cell::race::OnceBox;

use aes::{Aes128, Aes192, Aes256};
use alloc::vec;
use ctr::Ctr128BE;
use hashbrown::HashMap;
use litebox::{
    LiteBox,
    mm::{PageManager, linux::PAGE_SIZE},
    platform::{RawConstPointer as _, RawMutPointer as _},
};
use litebox_common_optee::{
    SyscallRequest, TeeAlgorithm, TeeAlgorithmClass, TeeAttributeType, TeeCrypStateHandle,
    TeeHandleFlag, TeeObjHandle, TeeObjectInfo, TeeObjectType, TeeOperationMode, TeeResult,
    UteeAttribute,
};
use litebox_platform_multiplex::Platform;

pub mod loader;
pub(crate) mod syscalls;

const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

/// Get the global litebox object
pub fn litebox<'a>() -> &'a LiteBox<Platform> {
    static LITEBOX: OnceBox<LiteBox<Platform>> = OnceBox::new();
    LITEBOX.get_or_init(|| {
        alloc::boxed::Box::new(LiteBox::new(litebox_platform_multiplex::platform()))
    })
}

pub(crate) fn litebox_page_manager<'a>() -> &'a PageManager<Platform, PAGE_SIZE> {
    static VMEM: OnceBox<PageManager<Platform, PAGE_SIZE>> = OnceBox::new();
    VMEM.get_or_init(|| alloc::boxed::Box::new(PageManager::new(litebox())))
}

// Convenience type aliases
type ConstPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

/// Handle OP-TEE syscalls
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development purposes.
#[allow(clippy::too_many_lines)]
pub fn handle_syscall_request(request: SyscallRequest<Platform>) -> u32 {
    let res: Result<(), TeeResult> = match request {
        SyscallRequest::Return { ret } => syscalls::tee::sys_return(ret),
        SyscallRequest::Log { buf, len } => match unsafe { buf.to_cow_slice(len) } {
            Some(buf) => syscalls::tee::sys_log(&buf),
            None => Err(TeeResult::BadParameters),
        },
        SyscallRequest::Panic { code } => syscalls::tee::sys_panic(code),
        SyscallRequest::GetProperty {
            prop_set,
            index,
            name,
            name_len,
            buf,
            blen,
            prop_type,
        } => {
            if let Some(buf_length) = unsafe { blen.read_at_offset(0) }
                && usize::try_from(*buf_length).unwrap() <= MAX_KERNEL_BUF_SIZE
            {
                let mut prop_buf = vec![0u8; usize::try_from(*buf_length).unwrap()];
                if name.as_usize() != 0 || name_len.as_usize() != 0 {
                    todo!("return the name of a given property index")
                }
                syscalls::tee::sys_get_property(
                    prop_set,
                    index,
                    None,
                    None,
                    &mut prop_buf,
                    blen,
                    prop_type,
                )
                .and_then(|()| {
                    buf.copy_from_slice(0, &prop_buf)
                        .ok_or(TeeResult::ShortBuffer)?;
                    Ok(())
                })
            } else {
                Err(TeeResult::BadParameters)
            }
        }
        SyscallRequest::GetPropertyNameToIndex {
            prop_set,
            name,
            name_len,
            index,
        } => match unsafe { name.to_cow_slice(name_len) } {
            Some(name) => syscalls::tee::sys_get_property_name_to_index(prop_set, &name, index),
            None => Err(TeeResult::BadParameters),
        },
        SyscallRequest::OpenTaSession {
            ta_uuid,
            cancel_req_to,
            usr_params,
            ta_sess_id,
            ret_orig,
        } => {
            if let Some(ta_uuid) = unsafe { ta_uuid.read_at_offset(0) }
                && let Some(usr_params) = unsafe { usr_params.read_at_offset(0) }
            {
                syscalls::tee::sys_open_ta_session(
                    *ta_uuid,
                    cancel_req_to,
                    *usr_params,
                    ta_sess_id,
                    ret_orig,
                )
            } else {
                Err(TeeResult::BadParameters)
            }
        }
        SyscallRequest::CloseTaSession { ta_sess_id } => {
            syscalls::tee::sys_close_ta_session(ta_sess_id)
        }
        SyscallRequest::InvokeTaCommand {
            ta_sess_id,
            cancel_req_to,
            cmd_id,
            params,
            ret_orig,
        } => {
            if let Some(params) = unsafe { params.read_at_offset(0) } {
                syscalls::tee::sys_invoke_ta_command(
                    ta_sess_id,
                    cancel_req_to,
                    cmd_id,
                    *params,
                    ret_orig,
                )
            } else {
                Err(TeeResult::BadParameters)
            }
        }
        SyscallRequest::CheckAccessRights { flags, buf, len } => {
            syscalls::tee::sys_check_access_rights(flags, buf, len)
        }
        SyscallRequest::CrypStateAlloc {
            algo,
            op_mode,
            key1,
            key2,
            state,
        } => syscalls::cryp::sys_cryp_state_alloc(algo, op_mode, key1, key2, state),
        SyscallRequest::CrypStateFree { state } => syscalls::cryp::sys_cryp_state_free(state),
        SyscallRequest::CipherInit { state, iv, iv_len } => {
            match unsafe { iv.to_cow_slice(iv_len) } {
                Some(iv) => syscalls::cryp::sys_cipher_init(state, &iv),
                None => Err(TeeResult::BadParameters),
            }
        }
        SyscallRequest::CipherUpdate {
            state,
            src,
            src_len,
            dst,
            dst_len,
        } => handle_cipher_update_or_final(
            state,
            src,
            src_len,
            dst,
            dst_len,
            syscalls::cryp::sys_cipher_update,
        ),
        SyscallRequest::CipherFinal {
            state,
            src,
            src_len,
            dst,
            dst_len,
        } => handle_cipher_update_or_final(
            state,
            src,
            src_len,
            dst,
            dst_len,
            syscalls::cryp::sys_cipher_final,
        ),
        SyscallRequest::CrypObjGetInfo { obj, info } => {
            syscalls::cryp::sys_cryp_obj_get_info(obj, info)
        }
        SyscallRequest::CrypObjAlloc { typ, max_size, obj } => {
            syscalls::cryp::sys_cryp_obj_alloc(typ, max_size, obj)
        }
        SyscallRequest::CrypObjClose { obj } => syscalls::cryp::sys_cryp_obj_close(obj),
        SyscallRequest::CrypObjReset { obj } => syscalls::cryp::sys_cryp_obj_reset(obj),
        SyscallRequest::CrypObjPopulate {
            obj,
            attrs,
            attr_count,
        } => match unsafe { attrs.to_cow_slice(attr_count) } {
            Some(attrs) => syscalls::cryp::sys_cryp_obj_populate(obj, &attrs),
            None => Err(TeeResult::BadParameters),
        },
        SyscallRequest::CrypObjCopy { dst_obj, src_obj } => {
            syscalls::cryp::sys_cryp_obj_copy(dst_obj, src_obj)
        }
        SyscallRequest::CrypRandomNumberGenerate { buf, blen } => {
            let mut kernel_buf = vec![0u8; blen.min(MAX_KERNEL_BUF_SIZE)];
            syscalls::cryp::sys_cryp_random_number_generate(&mut kernel_buf).and_then(|()| {
                buf.copy_from_slice(0, &kernel_buf)
                    .ok_or(TeeResult::ShortBuffer)
            })
        }
        _ => todo!(),
    };

    match res {
        Ok(()) => TeeResult::Success.into(),
        Err(e) => e.into(),
    }
}

#[inline]
fn handle_cipher_update_or_final<F>(
    state: TeeCrypStateHandle,
    src: ConstPtr<u8>,
    src_len: usize,
    dst: MutPtr<u8>,
    dst_len: MutPtr<u64>,
    syscall_fn: F,
) -> Result<(), TeeResult>
where
    F: Fn(TeeCrypStateHandle, &[u8], &mut [u8], &mut usize) -> Result<(), TeeResult>,
{
    if let Some(src_slice) = unsafe { src.to_cow_slice(src_len) }
        && let Some(length) = unsafe { dst_len.read_at_offset(0) }
        && usize::try_from(*length).unwrap() <= MAX_KERNEL_BUF_SIZE
    {
        let mut length = usize::try_from(*length).unwrap();
        let mut kernel_buf = vec![0u8; length];
        syscall_fn(state, &src_slice, &mut kernel_buf, &mut length).and_then(|()| {
            unsafe {
                let _ = dst_len.write_at_offset(0, u64::try_from(length).unwrap());
            }
            dst.copy_from_slice(0, &kernel_buf[..length])
                .ok_or(TeeResult::OutOfMemory)
        })
    } else {
        Err(TeeResult::BadParameters)
    }
}

/// A data structure to represent a TEE object referenced by `TeeObjHandle`.
/// This is an in-kernel data structure such that we can have our own
/// representation (i.e., doesn't have to match the original OP-TEE data structure).
///
/// NOTE: This data structure is unstable and can be changed in the future.
///
/// TODO: OP-TEE OS manages `TeeObj` per session and per handle.
#[derive(Clone)]
pub struct TeeObj {
    info: TeeObjectInfo,
    busy: bool,
    key: Option<alloc::boxed::Box<[u8]>>,
}

impl TeeObj {
    pub fn new(typ: TeeObjectType, max_size: u32) -> Self {
        TeeObj {
            info: TeeObjectInfo::new(typ, max_size),
            busy: false,
            key: None,
        }
    }

    pub fn info(&self) -> &TeeObjectInfo {
        &self.info
    }

    pub fn initialize(&mut self) {
        self.info
            .handle_flags
            .set(TeeHandleFlag::TEE_HANDLE_FLAG_INITIALIZED, true);
    }

    pub fn reset(&mut self) {
        self.info
            .handle_flags
            .set(TeeHandleFlag::TEE_HANDLE_FLAG_INITIALIZED, false);
        self.key = None;
    }

    pub fn set_key(&mut self, key: &[u8]) {
        self.key = Some(alloc::boxed::Box::from(key));
        self.info
            .handle_flags
            .set(TeeHandleFlag::TEE_HANDLE_FLAG_KEY_SET, true);
    }

    pub fn get_key(&self) -> Option<&[u8]> {
        if self.info.handle_flags.contains(
            TeeHandleFlag::TEE_HANDLE_FLAG_INITIALIZED | TeeHandleFlag::TEE_HANDLE_FLAG_KEY_SET,
        ) {
            self.key.as_deref()
        } else {
            None
        }
    }
}

pub(crate) struct TeeObjMap {
    inner: spin::mutex::SpinMutex<HashMap<TeeObjHandle, TeeObj>>,
}

impl TeeObjMap {
    pub fn new() -> Self {
        TeeObjMap {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn allocate(&self, tee_obj: &TeeObj) -> TeeObjHandle {
        let mut inner = self.inner.lock();
        let handle = match inner.keys().max() {
            Some(max_handle) => TeeObjHandle(max_handle.0 + 1),
            None => TeeObjHandle(1), // start from 1 since 0 means an invalid handle
        };
        inner.insert(handle, tee_obj.clone());
        handle
    }

    pub fn replace(&self, handle: TeeObjHandle, tee_obj: &TeeObj) {
        let mut inner = self.inner.lock();
        inner.insert(handle, tee_obj.clone());
    }

    pub fn populate(
        &self,
        handle: TeeObjHandle,
        user_attrs: &[UteeAttribute],
    ) -> Result<(), TeeResult> {
        let mut inner = self.inner.lock();
        if let Some(tee_obj) = inner.get_mut(&handle) {
            tee_obj.initialize();

            if user_attrs.is_empty() {
                return Ok(());
            }

            // TODO: support multiple attributes (e.g., two-key crypto algorithms like AES-XTS)
            match user_attrs[0].attribute_id {
                TeeAttributeType::SecretValue => {
                    let key_addr = user_attrs[0].a as *const u8;
                    let key_len = usize::try_from(user_attrs[0].b).unwrap();
                    let key_slice = unsafe { core::slice::from_raw_parts(key_addr, key_len) };
                    tee_obj.set_key(key_slice);
                }
                _ => todo!("handle attribute ID: {}", user_attrs[0].attribute_id as u32),
            }

            Ok(())
        } else {
            Err(TeeResult::ItemNotFound)
        }
    }

    pub fn reset(&self, handle: TeeObjHandle) -> Result<(), TeeResult> {
        let mut inner = self.inner.lock();
        if let Some(tee_obj) = inner.get_mut(&handle) {
            tee_obj.reset();
            Ok(())
        } else {
            Err(TeeResult::ItemNotFound)
        }
    }

    pub fn remove(&self, handle: TeeObjHandle) {
        self.inner.lock().remove(&handle);
    }

    pub fn exists(&self, handle: TeeObjHandle) -> bool {
        self.inner.lock().contains_key(&handle)
    }

    pub fn is_busy(&self, handle: TeeObjHandle) -> bool {
        self.inner.lock().get(&handle).is_some_and(|obj| obj.busy)
    }

    pub fn set_busy(&self, handle: TeeObjHandle, busy: bool) {
        if let Some(obj) = self.inner.lock().get_mut(&handle) {
            obj.busy = busy;
        }
    }

    pub fn get_copy(&self, handle: TeeObjHandle) -> Option<TeeObj> {
        self.inner.lock().get(&handle).cloned()
    }
}

pub(crate) fn tee_obj_map() -> &'static TeeObjMap {
    static TEE_OBJ_MAP: OnceBox<TeeObjMap> = OnceBox::new();
    TEE_OBJ_MAP.get_or_init(|| alloc::boxed::Box::new(TeeObjMap::new()))
}

/// A data structure to represent a TEE cryptography state referenced by `TeeCrypStateHandle`.
/// This is an in-kernel data structure such that we can have our own
/// representation (i.e., doesn't have to match the original OP-TEE data structure).
/// It has primary and secondary cryptography object and a cipher.
///
/// NOTE: This data structure is unstable and can be changed in the future.
#[derive(Clone)]
pub struct TeeCrypState {
    algo: TeeAlgorithm,
    mode: TeeOperationMode,
    objs: [Option<TeeObjHandle>; 2],
    cipher: Option<Cipher>,
}

impl TeeCrypState {
    pub fn new(
        algo: TeeAlgorithm,
        mode: TeeOperationMode,
        primary_object: Option<TeeObjHandle>,
        secondary_object: Option<TeeObjHandle>,
    ) -> Self {
        TeeCrypState {
            algo,
            mode,
            objs: [primary_object, secondary_object],
            cipher: None,
        }
    }

    pub fn algorithm(&self) -> TeeAlgorithm {
        self.algo
    }

    pub fn algorithm_class(&self) -> TeeAlgorithmClass {
        TeeAlgorithmClass::from(self.algo)
    }

    pub fn operation_mode(&self) -> TeeOperationMode {
        self.mode
    }

    pub fn get_object_handle(&self, is_primary: bool) -> Option<TeeObjHandle> {
        let index = usize::from(!is_primary);
        self.objs[index]
    }

    pub fn set_cipher(&mut self, cipher: &Cipher) {
        self.cipher = Some(cipher.clone());
    }

    pub fn get_mut_cipher(&mut self) -> Option<&mut Cipher> {
        self.cipher.as_mut()
    }
}

#[non_exhaustive]
#[derive(Clone)]
pub enum Cipher {
    Aes128Ctr(Ctr128BE<Aes128>),
    Aes192Ctr(Ctr128BE<Aes192>),
    Aes256Ctr(Ctr128BE<Aes256>),
}

/// A data structure to manage `TeeCrypState` per handle.
///
/// NOTE: This data structure is unstable and can be changed in the future.
///
/// TODO: OP-TEE OS manages `TeeCrypState` per session and per handle.
pub(crate) struct TeeCrypStateMap {
    inner: spin::mutex::SpinMutex<HashMap<TeeCrypStateHandle, TeeCrypState>>,
}

impl TeeCrypStateMap {
    pub fn new() -> Self {
        TeeCrypStateMap {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn allocate(&self, tee_cryp_state: &TeeCrypState) -> TeeCrypStateHandle {
        let mut inner = self.inner.lock();
        let handle = match inner.keys().max() {
            Some(max_handle) => TeeCrypStateHandle(max_handle.0 + 1),
            None => TeeCrypStateHandle(1), // start from 1 since 0 means an invalid handle
        };
        inner.insert(handle, tee_cryp_state.clone());
        handle
    }

    pub fn set_cipher(&self, handle: TeeCrypStateHandle, cipher: &Cipher) -> Result<(), TeeResult> {
        let mut inner = self.inner.lock();
        if let Some(state) = inner.get_mut(&handle) {
            state.cipher = Some(cipher.clone());
            Ok(())
        } else {
            Err(TeeResult::ItemNotFound)
        }
    }

    pub fn remove(&self, handle: TeeCrypStateHandle) {
        self.inner.lock().remove(&handle);
    }

    #[expect(dead_code)]
    pub fn exists(&self, handle: TeeCrypStateHandle) -> bool {
        self.inner.lock().contains_key(&handle)
    }

    pub fn get_copy(&self, handle: TeeCrypStateHandle) -> Option<TeeCrypState> {
        self.inner.lock().get(&handle).cloned()
    }

    pub fn get_mut(
        &self,
        handle: TeeCrypStateHandle,
    ) -> Option<spin::mutex::SpinMutexGuard<'_, HashMap<TeeCrypStateHandle, TeeCrypState>>> {
        let inner = self.inner.lock();
        if inner.contains_key(&handle) {
            Some(inner)
        } else {
            None
        }
    }
}

pub(crate) fn tee_cryp_state_map() -> &'static TeeCrypStateMap {
    static TEE_CRYPT_STATE_MAP: OnceBox<TeeCrypStateMap> = OnceBox::new();
    TEE_CRYPT_STATE_MAP.get_or_init(|| alloc::boxed::Box::new(TeeCrypStateMap::new()))
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides an OP-TEE-compatible ABI via LiteBox

#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

// TODO(jayb) Replace out all uses of once_cell and such with our own implementation that uses
// platform-specific things within it.
use once_cell::race::OnceBox;

use aes::{Aes128, Aes192, Aes256};
use alloc::{collections::vec_deque::VecDeque, sync::Arc, vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering::SeqCst};
use ctr::Ctr128BE;
use hashbrown::HashMap;
use litebox::{
    LiteBox,
    mm::{PageManager, linux::PAGE_SIZE},
    platform::{RawConstPointer as _, RawMutPointer as _},
    shim::ContinueOperation,
    utils::ReinterpretUnsignedExt,
};
use litebox_common_optee::{
    LdelfSyscallRequest, SyscallRequest, TeeAlgorithm, TeeAlgorithmClass, TeeAttributeType,
    TeeCrypStateHandle, TeeHandleFlag, TeeIdentity, TeeLogin, TeeObjHandle, TeeObjectInfo,
    TeeObjectType, TeeOperationMode, TeeResult, TeeUuid, UteeAttribute,
};
use litebox_platform_multiplex::Platform;

pub mod loader;
pub(crate) mod syscalls;

const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

pub struct OpteeShimEntrypoints {
    task: Task,
    // The task should not be moved once it's bound to a platform thread so that
    // we preserve the ability to use TLS in the future.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl litebox::shim::EnterShim for OpteeShimEntrypoints {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        ContinueOperation::ResumeGuest
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        if self.task.ta_loaded.load(SeqCst) {
            self.task.handle_syscall_request(ctx)
        } else {
            self.task.handle_ldelf_syscall_request(ctx)
        }
    }

    fn exception(
        &self,
        _ctx: &mut Self::ExecutionContext,
        info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        unimplemented!("Unhandled exception in OP-TEE shim: {:?}", info,);
    }

    fn interrupt(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        ContinueOperation::ResumeGuest
    }
}

/// The shim entry point structure.
pub struct OpteeShimBuilder {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
}

impl Default for OpteeShimBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl OpteeShimBuilder {
    /// Returns a new shim builder.
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            platform,
            litebox: LiteBox::new(platform),
        }
    }

    /// Returns the litebox object for the shim.
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Build the shim.
    ///
    /// # Panics
    /// Panics if the file system has not been set with [`set_fs`](Self::set_fs)
    /// before calling this method.
    pub fn build(self) -> OpteeShim {
        let global = Arc::new(GlobalState {
            platform: self.platform,
            pm: PageManager::new(&self.litebox),
            _litebox: self.litebox,
            session_id_pool: SessionIdPool::new(),
            ta_uuid_map: TaUuidMap::new(),
        });
        OpteeShim(global)
    }
}

/// Global shim state, shared across all tasks.
struct GlobalState {
    /// The platform instance used throughout the shim.
    platform: &'static Platform,
    /// The page manager for managing virtual memory.
    pm: litebox::mm::PageManager<Platform, { PAGE_SIZE }>,
    /// The LiteBox instance used throughout the shim.
    _litebox: litebox::LiteBox<Platform>,
    /// Session ID pool.
    session_id_pool: SessionIdPool,
    /// The TA UUID to binary map for TA loading.
    ta_uuid_map: TaUuidMap,
}

type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;

type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

#[derive(Clone)]
pub struct OpteeShim(Arc<GlobalState>);

impl OpteeShim {
    /// Load the given `ldelf` binary into memory while making it ready to load the TA binary specified
    /// by `ta_uuid` (and optionally `ta_bin`). `client` specifies the one requesting the TA load.
    pub fn load_ldelf(
        &self,
        ldelf_bin: &[u8],
        ta_uuid: TeeUuid,
        ta_bin: Option<&[u8]>,
        client: Option<TeeIdentity>,
    ) -> Result<(LoadedTa, litebox_common_linux::PtRegs), loader::elf::ElfLoaderError> {
        let entrypoints = crate::OpteeShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.0.clone(),
                session_id: self.0.session_id_pool.allocate(),
                ta_app_id: ta_uuid,
                client_identity: client.unwrap_or(TeeIdentity {
                    login: TeeLogin::User,
                    uuid: TeeUuid::default(),
                }),
                tee_cryp_state_map: TeeCrypStateMap::new(),
                tee_obj_map: TeeObjMap::new(),
                ta_loaded: AtomicBool::new(false),
                ta_base_addr: AtomicUsize::new(0),
                ta_handle_map: TaHandleMap::new(),
                ta_stack_base_addr: AtomicUsize::new(0),
                ta_entry_point: AtomicUsize::new(0),
            },
        };
        let mut elf_loader = loader::elf::ElfLoader::new(&entrypoints.task, ldelf_bin)?;
        let ctx = elf_loader.load_ldelf(ta_uuid, ta_bin)?;

        Ok((LoadedTa { entrypoints }, ctx))
    }

    /// Get the global page manager
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.0.pm
    }
}

impl OpteeShimEntrypoints {
    pub fn load_ta_context(
        &mut self,
        params: &[litebox_common_optee::UteeParamOwned],
        session_id: Option<u32>,
        func_id: u32,
        cmd_id: Option<u32>,
    ) -> Result<litebox_common_linux::PtRegs, loader::elf::ElfLoaderError> {
        crate::loader::elf::load_ta_context(&mut self.task, params, session_id, func_id, cmd_id)
    }

    pub fn get_session_id(&self) -> u32 {
        self.task.session_id
    }
}

pub struct LoadedTa {
    pub entrypoints: OpteeShimEntrypoints,
}

impl Task {
    /// Handle OP-TEE syscalls
    ///
    /// # Panics
    ///
    /// Unsupported syscalls or arguments would trigger a panic for development purposes.
    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation {
        let request = match SyscallRequest::<Platform>::try_from_raw(ctx.orig_rax, ctx) {
            Ok(request) => request,
            Err(err) => {
                // TODO: this seems like the wrong kind of error for OPTEE.
                ctx.rax = (err.as_neg() as isize).reinterpret_as_unsigned();
                return ContinueOperation::ResumeGuest;
            }
        };

        if let SyscallRequest::Return { ret } = request {
            ctx.rax = self.sys_return(ret);
            return ContinueOperation::ExitThread;
        } else if let SyscallRequest::Panic { code } = request {
            ctx.rax = self.sys_panic(code);
            return ContinueOperation::ExitThread;
        }
        let res: Result<(), TeeResult> = match request {
            SyscallRequest::Log { buf, len } => match unsafe { buf.to_cow_slice(len) } {
                Some(buf) => self.sys_log(&buf),
                None => Err(TeeResult::BadParameters),
            },
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
                    self.sys_get_property(
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
                Some(name) => Task::sys_get_property_name_to_index(prop_set, &name, index),
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
                    Task::sys_open_ta_session(
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
            SyscallRequest::CloseTaSession { ta_sess_id } => Task::sys_close_ta_session(ta_sess_id),
            SyscallRequest::InvokeTaCommand {
                ta_sess_id,
                cancel_req_to,
                cmd_id,
                params,
                ret_orig,
            } => {
                if let Some(params) = unsafe { params.read_at_offset(0) } {
                    self.sys_invoke_ta_command(ta_sess_id, cancel_req_to, cmd_id, *params, ret_orig)
                } else {
                    Err(TeeResult::BadParameters)
                }
            }
            SyscallRequest::CheckAccessRights { flags, buf, len } => {
                self.sys_check_access_rights(flags, buf, len)
            }
            SyscallRequest::CrypStateAlloc {
                algo,
                op_mode,
                key1,
                key2,
                state,
            } => self.sys_cryp_state_alloc(algo, op_mode, key1, key2, state),
            SyscallRequest::CrypStateFree { state } => self.sys_cryp_state_free(state),
            SyscallRequest::CipherInit { state, iv, iv_len } => {
                match unsafe { iv.to_cow_slice(iv_len) } {
                    Some(iv) => self.sys_cipher_init(state, &iv),
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
                self,
                state,
                src,
                src_len,
                dst,
                dst_len,
                Task::sys_cipher_update,
            ),
            SyscallRequest::CipherFinal {
                state,
                src,
                src_len,
                dst,
                dst_len,
            } => handle_cipher_update_or_final(
                self,
                state,
                src,
                src_len,
                dst,
                dst_len,
                Task::sys_cipher_final,
            ),
            SyscallRequest::CrypObjGetInfo { obj, info } => self.sys_cryp_obj_get_info(obj, info),
            SyscallRequest::CrypObjAlloc { typ, max_size, obj } => {
                self.sys_cryp_obj_alloc(typ, max_size, obj)
            }
            SyscallRequest::CrypObjClose { obj } => self.sys_cryp_obj_close(obj),
            SyscallRequest::CrypObjReset { obj } => self.sys_cryp_obj_reset(obj),
            SyscallRequest::CrypObjPopulate {
                obj,
                attrs,
                attr_count,
            } => match unsafe { attrs.to_cow_slice(attr_count) } {
                Some(attrs) => self.sys_cryp_obj_populate(obj, &attrs),
                None => Err(TeeResult::BadParameters),
            },
            SyscallRequest::CrypObjCopy { dst_obj, src_obj } => {
                self.sys_cryp_obj_copy(dst_obj, src_obj)
            }
            SyscallRequest::CrypRandomNumberGenerate { buf, blen } => {
                // This could take a long time for large sizes. But OP-TEE OS limits
                // the maximum size of random data generation to 4096 bytes, so
                // let's do the same rather than something more complicated.
                if blen > 4096 {
                    Err(TeeResult::OutOfMemory)
                } else {
                    let mut kernel_buf = vec![0u8; blen];
                    self.sys_cryp_random_number_generate(&mut kernel_buf)
                        .and_then(|()| {
                            buf.copy_from_slice(0, &kernel_buf)
                                .ok_or(TeeResult::AccessDenied)
                        })
                }
            }
            _ => todo!(),
        };

        ctx.rax = match res {
            Ok(()) => u32::from(TeeResult::Success),
            Err(e) => e.into(),
        } as usize;
        ContinueOperation::ResumeGuest
    }

    fn handle_ldelf_syscall_request(
        &self,
        ctx: &mut litebox_common_linux::PtRegs,
    ) -> ContinueOperation {
        let request = match LdelfSyscallRequest::<Platform>::try_from_raw(ctx.orig_rax, ctx) {
            Ok(request) => request,
            Err(err) => {
                // TODO: this seems like the wrong kind of error for OPTEE.
                ctx.rax = (err.as_neg() as isize).reinterpret_as_unsigned();
                return ContinueOperation::ResumeGuest;
            }
        };

        if let LdelfSyscallRequest::Return { ret } = request {
            ctx.rax = self.sys_return(ret);
            return ContinueOperation::ExitThread;
        } else if let LdelfSyscallRequest::Panic { code } = request {
            ctx.rax = self.sys_panic(code);
            return ContinueOperation::ExitThread;
        }
        let res: Result<(), TeeResult> = match request {
            LdelfSyscallRequest::Log { buf, len } => match unsafe { buf.to_cow_slice(len) } {
                Some(buf) => self.sys_log(&buf),
                None => Err(TeeResult::BadParameters),
            },
            LdelfSyscallRequest::MapZi {
                va,
                num_bytes,
                pad_begin,
                pad_end,
                flags,
            } => self.sys_map_zi(va, num_bytes, pad_begin, pad_end, flags),
            LdelfSyscallRequest::OpenBin {
                uuid,
                uuid_size,
                handle,
            } => {
                if uuid_size == core::mem::size_of::<TeeUuid>()
                    && let Some(ta_uuid) = unsafe { uuid.read_at_offset(0) }
                {
                    self.sys_open_bin(*ta_uuid, handle)
                } else {
                    Err(TeeResult::BadParameters)
                }
            }
            LdelfSyscallRequest::CloseBin { handle } => self.sys_close_bin(handle),
            LdelfSyscallRequest::MapBin {
                va,
                num_bytes,
                handle,
                offs,
                pad_begin,
                pad_end,
                flags,
            } => self.sys_map_bin(va, num_bytes, handle, offs, pad_begin, pad_end, flags),
            LdelfSyscallRequest::CpFromBin {
                dst,
                offs,
                num_bytes,
                handle,
            } => self.sys_cp_from_bin(dst, offs, num_bytes, handle),
            LdelfSyscallRequest::GenRndNum { buf, num_bytes } => {
                // This could take a long time for large sizes. But OP-TEE OS limits
                // the maximum size of random data generation to 4096 bytes, so
                // let's do the same rather than something more complicated.
                if num_bytes > 4096 {
                    Err(TeeResult::OutOfMemory)
                } else {
                    let mut kernel_buf = vec![0u8; num_bytes];
                    self.sys_cryp_random_number_generate(&mut kernel_buf)
                        .and_then(|()| {
                            buf.copy_from_slice(0, &kernel_buf)
                                .ok_or(TeeResult::AccessDenied)
                        })
                }
            }
            _ => todo!(),
        };

        ctx.rax = match res {
            Ok(()) => u32::from(TeeResult::Success),
            Err(e) => e.into(),
        } as usize;
        ContinueOperation::ResumeGuest
    }

    // Set the base address of the loaded TA for the current task.
    // This address is used for loading the TA's trampoline.
    pub(crate) fn set_ta_base_addr(&self, addr: usize) {
        self.ta_base_addr.store(addr, SeqCst);
    }

    // Get the base address of the loaded TA for the current task.
    // This address is used for loading the TA's trampoline.
    pub(crate) fn get_ta_base_addr(&self) -> Option<usize> {
        let addr = self.ta_base_addr.load(SeqCst);
        if addr == 0 { None } else { Some(addr) }
    }

    /// Set the base address of the TA stack for the current task.
    pub(crate) fn set_ta_stack_base_addr(&self, addr: usize) {
        self.ta_stack_base_addr.store(addr, SeqCst);
    }

    /// Get the base address of the TA stack for the current task.
    pub(crate) fn get_ta_stack_base_addr(&self) -> Option<usize> {
        let addr = self.ta_stack_base_addr.load(SeqCst);
        if addr == 0 { None } else { Some(addr) }
    }

    /// Set the entry point of the TA for the current task.
    pub(crate) fn set_ta_entry_point(&self, addr: usize) {
        self.ta_entry_point.store(addr, SeqCst);
    }

    /// Get the entry point of the TA for the current task.
    pub(crate) fn get_ta_entry_point(&self) -> usize {
        self.ta_entry_point.load(SeqCst)
    }
}

#[inline]
fn handle_cipher_update_or_final<F>(
    task: &Task,
    state: TeeCrypStateHandle,
    src: UserConstPtr<u8>,
    src_len: usize,
    dst: UserMutPtr<u8>,
    dst_len: UserMutPtr<u64>,
    syscall_fn: F,
) -> Result<(), TeeResult>
where
    F: Fn(&Task, TeeCrypStateHandle, &[u8], &mut [u8], &mut usize) -> Result<(), TeeResult>,
{
    if let Some(src_slice) = unsafe { src.to_cow_slice(src_len) }
        && let Some(length) = unsafe { dst_len.read_at_offset(0) }
        && usize::try_from(*length).unwrap() <= MAX_KERNEL_BUF_SIZE
    {
        let mut length = usize::try_from(*length).unwrap();
        let mut kernel_buf = vec![0u8; length];
        syscall_fn(task, state, &src_slice, &mut kernel_buf, &mut length).and_then(|()| {
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
#[derive(Clone)]
pub(crate) struct TeeObj {
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

    #[expect(dead_code)]
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

/// A data structure to represent a TEE cryptography state referenced by `TeeCrypStateHandle`.
/// This is an in-kernel data structure such that we can have our own
/// representation (i.e., doesn't have to match the original OP-TEE data structure).
/// It has primary and secondary cryptography object and a cipher.
///
/// NOTE: This data structure is unstable and can be changed in the future.
#[derive(Clone)]
pub(crate) struct TeeCrypState {
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

    #[expect(dead_code)]
    pub fn operation_mode(&self) -> TeeOperationMode {
        self.mode
    }

    pub fn get_object_handle(&self, is_primary: bool) -> Option<TeeObjHandle> {
        let index = usize::from(!is_primary);
        self.objs[index]
    }

    #[expect(dead_code)]
    pub fn set_cipher(&mut self, cipher: &Cipher) {
        self.cipher = Some(cipher.clone());
    }

    pub fn get_mut_cipher(&mut self) -> Option<&mut Cipher> {
        self.cipher.as_mut()
    }
}

#[allow(clippy::enum_variant_names)]
#[non_exhaustive]
#[derive(Clone)]
pub(crate) enum Cipher {
    Aes128Ctr(Ctr128BE<Aes128>),
    Aes192Ctr(Ctr128BE<Aes192>),
    Aes256Ctr(Ctr128BE<Aes256>),
}

/// A data structure to manage `TeeCrypState` per handle.
///
/// NOTE: This data structure is unstable and can be changed in the future.
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

/// Data structure to maintain a mapping from handles to their TA UUIDs.
pub(crate) struct TaHandleMap {
    inner: spin::mutex::SpinMutex<HashMap<u32, TeeUuid>>,
    next_handle: core::sync::atomic::AtomicU32,
}

impl TaHandleMap {
    pub(crate) fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
            next_handle: 1.into(),
        }
    }

    pub(crate) fn insert(&self, uuid: TeeUuid) -> u32 {
        let handle = self
            .next_handle
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        let mut inner = self.inner.lock();
        inner.insert(handle, uuid);
        handle
    }

    pub(crate) fn get(&self, handle: u32) -> Option<TeeUuid> {
        self.inner.lock().get(&handle).copied()
    }

    pub(crate) fn remove(&self, handle: u32) -> Option<TeeUuid> {
        self.inner.lock().remove(&handle)
    }
}

/// Data structure to maintain a mapping from TA UUIDs to their binary data.
pub(crate) struct TaUuidMap {
    inner: spin::mutex::SpinMutex<HashMap<TeeUuid, alloc::boxed::Box<[u8]>>>,
}

impl TaUuidMap {
    pub(crate) fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub(crate) fn insert(&self, uuid: TeeUuid, ta_bin: alloc::boxed::Box<[u8]>) {
        let mut inner = self.inner.lock();
        inner.insert(uuid, ta_bin);
    }

    pub(crate) fn get(&self, uuid: &TeeUuid) -> Option<alloc::boxed::Box<[u8]>> {
        self.inner.lock().get(uuid).cloned()
    }

    pub(crate) fn remove(&self, uuid: &TeeUuid) -> Option<alloc::boxed::Box<[u8]>> {
        self.inner.lock().remove(uuid)
    }
}

// TODO: OP-TEE supports global, persistent objects across sessions. Implement this map if needed.

// Each OP-TEE TA has its own UUID.
// The client of a session can be a normal-world (VTL0) application or another TA (at VTL1).
// The VTL0 kernel is expected to provide the client identity information.

/// TA/session-related information for the current task
struct Task {
    global: Arc<GlobalState>,
    /// Session ID
    session_id: u32,
    /// TA UUID
    ta_app_id: TeeUuid,
    /// Client identity (VTL0 process or another TA)
    client_identity: TeeIdentity,
    /// TEE cryptography state map (per session)
    tee_cryp_state_map: TeeCrypStateMap,
    /// TEE object map (per session)
    tee_obj_map: TeeObjMap,
    /// Track whether a TA is loaded via ldelf
    ta_loaded: AtomicBool,
    /// Base address where the TA is loaded
    ta_base_addr: AtomicUsize,
    /// TA handle to UUID map
    ta_handle_map: TaHandleMap,
    /// TA stack base addr
    ta_stack_base_addr: AtomicUsize,
    /// TA entry point
    ta_entry_point: AtomicUsize,
    // TODO: add more fields as needed
}

impl Drop for Task {
    fn drop(&mut self) {
        self.global.session_id_pool.recycle(self.session_id);
    }
}

pub struct SessionIdPool {
    inner: spin::mutex::SpinMutex<VecDeque<u32>>,
    next_session_id: AtomicU32,
}

impl SessionIdPool {
    const PTA_SESSION_ID: u32 = 0xffff_fffe;

    pub fn new() -> Self {
        SessionIdPool {
            inner: spin::mutex::SpinMutex::new(VecDeque::new()),
            next_session_id: 1.into(),
        }
    }

    /// # Panics
    /// Panics if session IDs are exhausted.
    pub fn allocate(&self) -> u32 {
        let mut inner = self.inner.lock();
        if let Some(session_id) = inner.pop_front() {
            session_id
        } else {
            let session_id = self.next_session_id.fetch_add(1, SeqCst);
            assert!(session_id != Self::PTA_SESSION_ID, "session ID exhausted");
            session_id
        }
    }

    pub fn recycle(&self, session_id: u32) {
        let mut inner = self.inner.lock();
        inner.push_back(session_id);
    }

    pub fn get_pta_session_id() -> u32 {
        Self::PTA_SESSION_ID
    }
}

impl Default for SessionIdPool {
    fn default() -> Self {
        Self::new()
    }
}

mod test_utils {
    use super::*;

    impl GlobalState {
        /// Make a new task with default values for testing.
        pub(crate) fn new_test_task(self: Arc<Self>) -> Task {
            Task {
                global: self.clone(),
                session_id: self.session_id_pool.allocate(),
                ta_app_id: TeeUuid::default(),
                client_identity: TeeIdentity {
                    login: TeeLogin::User,
                    uuid: TeeUuid::default(),
                },
                tee_cryp_state_map: TeeCrypStateMap::new(),
                tee_obj_map: TeeObjMap::new(),
                ta_loaded: AtomicBool::new(false),
                ta_base_addr: AtomicUsize::new(0),
                ta_handle_map: TaHandleMap::new(),
                ta_stack_base_addr: AtomicUsize::new(0),
                ta_entry_point: AtomicUsize::new(0),
            }
        }
    }
}

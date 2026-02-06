// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides an OP-TEE-compatible ABI via LiteBox

#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

use crate::loader::elf::ElfLoaderError;
use aes::{Aes128, Aes192, Aes256};
use alloc::{sync::Arc, vec};
use core::cell::Cell;
use ctr::Ctr128BE;
use hashbrown::HashMap;
use litebox::{
    LiteBox,
    mm::{PageManager, linux::PAGE_SIZE},
    platform::{PunchthroughProvider, PunchthroughToken, RawConstPointer as _, RawMutPointer as _},
    shim::ContinueOperation,
    utils::{ReinterpretUnsignedExt, TruncateExt},
};
use litebox_common_linux::{MapFlags, ProtFlags, errno::Errno};
use litebox_common_optee::{
    LdelfArg, LdelfSyscallRequest, SyscallRequest, TaFlags, TeeAlgorithm, TeeAlgorithmClass,
    TeeAttributeType, TeeCrypStateHandle, TeeHandleFlag, TeeIdentity, TeeLogin, TeeObjHandle,
    TeeObjectInfo, TeeObjectType, TeeOperationMode, TeeResult, TeeUuid, UteeAttribute,
};
use litebox_platform_multiplex::Platform;

pub mod loader;
pub mod session;
pub(crate) mod syscalls;

pub mod msg_handler;
pub mod ptr;

// Re-export session management types for convenience
pub use session::{
    MAX_TA_INSTANCES, SessionEntry, SessionManager, SessionMap, SingleInstanceCache, TaInstance,
    allocate_session_id, recycle_session_id,
};

const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

pub struct OpteeShimEntrypoints {
    task: Task,
    // The task should not be moved once it's bound to a platform thread so that
    // we preserve the ability to use TLS in the future.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl litebox::shim::EnterShim for OpteeShimEntrypoints {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(true, ctx, Task::handle_init_request)
    }

    fn reenter(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, Task::handle_reenter_request)
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, Task::handle_syscall_request)
    }

    fn exception(
        &self,
        _ctx: &mut Self::ExecutionContext,
        info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        todo!("Handle exception in OP-TEE shim: {:?}", info,);
    }

    fn interrupt(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        todo!("Handle interrupt in OP-TEE shim");
    }
}

impl OpteeShimEntrypoints {
    fn enter_shim(
        &self,
        _is_init: bool,
        ctx: &mut litebox_common_linux::PtRegs,
        f: impl FnOnce(&Task, &mut litebox_common_linux::PtRegs) -> ContinueOperation,
    ) -> ContinueOperation {
        f(&self.task, ctx)
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
    pub fn build(self) -> OpteeShim {
        let global = Arc::new(GlobalState {
            platform: self.platform,
            pm: PageManager::new(&self.litebox),
            _litebox: self.litebox,
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
    /// The TA UUID to binary map for TA loading.
    ta_uuid_map: TaUuidMap,
}

impl GlobalState {
    /// Store the TA binary associated with the given TA UUID.
    ///
    /// Returns `true` if the binary was successfully stored, `false` if the binary's
    /// UUID (from `.ta_head` section) doesn't match the provided UUID or parsing failed.
    pub(crate) fn store_ta_bin(&self, ta_uuid: &TeeUuid, ta_bin: &[u8]) -> bool {
        self.ta_uuid_map.insert(*ta_uuid, ta_bin.into())
    }

    /// Get the TA binary associated with the given TA UUID.
    pub(crate) fn get_ta_bin(&self, ta_uuid: &TeeUuid) -> Option<alloc::boxed::Box<[u8]>> {
        if let Some(ta_bin) = self.ta_uuid_map.get(ta_uuid) {
            Some(ta_bin)
        } else {
            let ta_bin = Self::rpc_get_ta_bin(ta_uuid)?;
            if !self.store_ta_bin(ta_uuid, &ta_bin) {
                return None;
            }
            Some(ta_bin)
        }
    }

    /// Get the TA flags associated with the given TA UUID.
    pub(crate) fn get_ta_flags(&self, ta_uuid: &TeeUuid) -> TaFlags {
        self.ta_uuid_map.get_flags(ta_uuid).unwrap_or_default()
    }

    /// Remove the TA binary associated with the given TA UUID.
    ///
    /// Since a TA binary can be continuously loaded/used by multiple clients, we cache it
    /// to avoid repeated RPCs and memory transfers. We remove it lazily if there is
    /// a memory pressure.
    ///
    /// TODO: Use something like `Arc` to to ensure no active ldelf/TA holds a handle to
    /// this TA binary
    #[expect(dead_code)]
    pub(crate) fn remove_ta_bin(&self, ta_uuid: &TeeUuid) {
        let _ = self.ta_uuid_map.remove(ta_uuid);
    }

    /// RPC to get the TA binary associated with the given TA UUID. Placeholder for now.
    fn rpc_get_ta_bin(_ta_uuid: &TeeUuid) -> Option<alloc::boxed::Box<[u8]>> {
        None
    }
}

type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
pub type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
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
        session_id: u32,
    ) -> Result<LoadedProgram, loader::elf::ElfLoaderError> {
        let entrypoints = crate::OpteeShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.0.clone(),
                thread: ThreadState::new(),
                session_id,
                ta_app_id: ta_uuid,
                client_identity: client.unwrap_or(TeeIdentity {
                    login: TeeLogin::User,
                    uuid: TeeUuid::default(),
                }),
                tee_cryp_state_map: TeeCrypStateMap::new(),
                tee_obj_map: TeeObjMap::new(),
                ta_handle_map: TaHandleMap::new(),
                ta_entry_point: Cell::new(0),
                ta_stack_base_addr: Cell::new(0),
                ta_prepared: Cell::new(false),
                #[cfg(target_arch = "x86_64")]
                tls_base_addr: Cell::new(0),
            },
        };
        if let Some(ta_bin) = ta_bin
            && !entrypoints.task.global.store_ta_bin(&ta_uuid, ta_bin)
        {
            return Err(loader::elf::ElfLoaderError::InvalidUuid);
        }
        let elf_loader = loader::elf::ElfLoader::new(&entrypoints.task, ldelf_bin, true)?;
        entrypoints.task.load_ldelf(elf_loader, ta_uuid)?;
        let params_address = if entrypoints.task.get_ta_stack_base_addr().is_some() {
            let ta_stack = crate::loader::ta_stack::allocate_stack(
                &entrypoints.task,
                entrypoints.task.get_ta_stack_base_addr(),
            )
            .ok_or(loader::elf::ElfLoaderError::MappingError(
                litebox::mm::linux::MappingError::OutOfMemory,
            ))?;
            Some(ta_stack.get_params_address())
        } else {
            None
        };
        // Get TA flags from the stored binary
        let ta_flags = entrypoints.task.global.get_ta_flags(&ta_uuid);
        Ok(LoadedProgram {
            entrypoints: Some(entrypoints),
            params_address,
            ta_flags,
        })
    }

    /// Get the global page manager
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.0.pm
    }
}

impl OpteeShimEntrypoints {
    /// Load the CPU context to (re)enter the loaded TA.
    pub fn load_ta_context(
        &self,
        params: &[litebox_common_optee::UteeParamOwned],
        session_id: Option<u32>,
        func_id: u32,
        cmd_id: Option<u32>,
    ) -> Result<(), loader::elf::ElfLoaderError> {
        let init_state = self
            .task
            .load_ta_context(params, session_id, func_id, cmd_id)?;
        self.task.thread.init_state.set(init_state);
        Ok(())
    }

    pub fn get_session_id(&self) -> u32 {
        self.task.session_id
    }
}

/// Information about a loaded TA program.
pub struct LoadedProgram {
    /// The entrypoints for the TA (syscall handling, context loading, etc.)
    pub entrypoints: Option<OpteeShimEntrypoints>,
    /// Address where TA parameters (`UteeParams`) are stored on the stack.
    ///
    /// This address is constant for the lifetime of the TA instance because:
    /// 1. The stack buffer is allocated once during initial loading (for ldelf)
    /// 2. Subsequent TA invocations reuse the same stack buffer
    /// 3. `UteeParams` is always placed at a fixed offset from the stack base
    ///    (`stack_top + stack_len - sizeof(UteeParams)`)
    ///
    /// The stack contents (including `UteeParams` values) are reinitialized on each
    /// `load_ta_context` call, but the address remains the same.
    pub params_address: Option<usize>,
    /// TA flags parsed from the `.ta_head` section
    pub ta_flags: TaFlags,
}

impl Task {
    /// Handle OP-TEE syscalls
    ///
    /// It dispatches the syscall handling based on the current thread initialization state (ldelf or TA).
    ///
    /// # Panics
    ///
    /// Unsupported syscalls or arguments would trigger a panic for development purposes.
    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation {
        match self.thread.init_state.get() {
            ThreadInitState::None => ContinueOperation::ExitThread,
            ThreadInitState::Ldelf { .. } => self.handle_ldelf_syscall_request(ctx),
            ThreadInitState::Ta { .. } => self.handle_ta_syscall_request(ctx),
        }
    }

    fn handle_ta_syscall_request(
        &self,
        ctx: &mut litebox_common_linux::PtRegs,
    ) -> ContinueOperation {
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
            SyscallRequest::Log { buf, len } => match buf.to_owned_slice(len) {
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
                if let Some(buf_length) = blen.read_at_offset(0)
                    && usize::try_from(buf_length).unwrap() <= MAX_KERNEL_BUF_SIZE
                {
                    let mut prop_buf = vec![0u8; usize::try_from(buf_length).unwrap()];
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
            } => match name.to_owned_slice(name_len) {
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
                if let Some(ta_uuid) = ta_uuid.read_at_offset(0)
                    && let Some(usr_params) = usr_params.read_at_offset(0)
                {
                    Task::sys_open_ta_session(
                        ta_uuid,
                        cancel_req_to,
                        usr_params,
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
                if let Some(params) = params.read_at_offset(0) {
                    self.sys_invoke_ta_command(ta_sess_id, cancel_req_to, cmd_id, params, ret_orig)
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
            SyscallRequest::CipherInit { state, iv, iv_len } => match iv.to_owned_slice(iv_len) {
                Some(iv) => self.sys_cipher_init(state, &iv),
                None => Err(TeeResult::BadParameters),
            },
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
            } => match attrs.to_owned_slice(attr_count) {
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

    fn handle_init_request(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation {
        // Ensure handle_init_request is invoked at most once.
        if self.thread.initialized.replace(true) {
            return ContinueOperation::ExitThread;
        }

        match self.thread.init_state.get() {
            ThreadInitState::None | ThreadInitState::Ta { .. } => ContinueOperation::ExitThread,
            ThreadInitState::Ldelf {
                ldelf_arg_address,
                entry_point,
                stack_top,
            } => {
                #[cfg(target_arch = "x86_64")]
                {
                    ctx.rdi = ldelf_arg_address;
                    ctx.rip = entry_point;
                    ctx.rsp = stack_top;
                    ctx.cs = 0x33; // __USER_CS
                    ctx.ss = 0x2b; // __USER_DS
                    ctx.eflags = 0x202; // IF (interrupt enable) and reserved bit 1
                }
                ContinueOperation::ResumeGuest
            }
        }
    }

    /// Handle a reentry request for an already loaded TA.
    ///
    /// Unlike `handle_init_request`, this function is used to re-enter
    /// a program or library that is already loaded in memory.
    ///
    /// TODO: We can re-enter `ldelf` as well to use its extra functions
    /// such as ftrace. Let's revisit this later.
    fn handle_reenter_request(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation {
        let state = self.thread.init_state.get();
        match state {
            ThreadInitState::None | ThreadInitState::Ldelf { .. } => ContinueOperation::ExitThread,
            ThreadInitState::Ta {
                cmd_id,
                params_address,
                session_id,
                func_id,
                entry_point,
                stack_top,
            } => {
                #[cfg(target_arch = "x86_64")]
                {
                    ctx.rdi = func_id;
                    ctx.rsi = session_id;
                    ctx.rdx = params_address;
                    ctx.rcx = cmd_id;
                    ctx.rip = entry_point;
                    ctx.rsp = stack_top;
                    ctx.cs = 0x33; // __USER_CS
                    ctx.ss = 0x2b; // __USER_DS
                    ctx.eflags = 0x202; // IF (interrupt enable) and reserved bit 1
                }
                ContinueOperation::ResumeGuest
            }
        }
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
            if ctx.rax == 0 {
                self.get_ldelf_result();
            }
            return ContinueOperation::ExitThread;
        } else if let LdelfSyscallRequest::Panic { code } = request {
            ctx.rax = self.sys_panic(code);
            return ContinueOperation::ExitThread;
        }
        let res: Result<(), TeeResult> = match request {
            LdelfSyscallRequest::Log { buf, len } => match buf.to_owned_slice(len) {
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
                    && let Some(ta_uuid) = uuid.read_at_offset(0)
                {
                    self.sys_open_bin(ta_uuid, handle)
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

    /// Load `ldelf` and prepare the stack and CPU context for it with the given TA UUID.
    fn load_ldelf(
        &self,
        mut loader: crate::loader::elf::ElfLoader<'_>,
        ta_uuid: TeeUuid,
    ) -> Result<(), ElfLoaderError> {
        let ldelf_arg = LdelfArg::new(ta_uuid);
        let init_state = loader.load_ldelf(&ldelf_arg)?;
        self.thread.init_state.set(init_state);
        Ok(())
    }

    /// Load the CPU context to (re)enter the loaded TA.
    fn load_ta_context(
        &self,
        params: &[litebox_common_optee::UteeParamOwned],
        session_id: Option<u32>,
        func_id: u32,
        cmd_id: Option<u32>,
    ) -> Result<ThreadInitState, ElfLoaderError> {
        if !self.ta_prepared.get() {
            let ta_bin = self
                .global
                .get_ta_bin(&self.ta_app_id)
                .ok_or(ElfLoaderError::OpenError(Errno::ENOENT))?;
            let ta_entry_point = self.get_ta_entry_point();
            let mut elf_loader = loader::elf::ElfLoader::new(self, &ta_bin, false)?;
            elf_loader.load_ta_trampoline(ta_entry_point)?;
            self.allocate_guest_tls(None).map_err(|_| {
                ElfLoaderError::MappingError(litebox::mm::linux::MappingError::OutOfMemory)
            })?;
            self.ta_prepared.set(true);
        }

        #[cfg(target_arch = "x86_64")]
        self.restore_guest_tls();

        let mut ta_stack =
            crate::loader::ta_stack::allocate_stack(self, self.get_ta_stack_base_addr()).ok_or(
                ElfLoaderError::MappingError(litebox::mm::linux::MappingError::OutOfMemory),
            )?;
        ta_stack
            .init(params)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;

        Ok(ThreadInitState::Ta {
            cmd_id: usize::try_from(cmd_id.unwrap_or(0)).unwrap(),
            params_address: ta_stack.get_params_address(),
            session_id: usize::try_from(session_id.unwrap_or(self.session_id)).unwrap(),
            func_id: usize::try_from(func_id).unwrap(),
            entry_point: self.get_ta_entry_point(),
            stack_top: ta_stack.get_cur_stack_top(),
        })
    }

    /// Allocate the guest TLS for an OP-TEE TA.
    ///
    /// This function is required to overcome the compatibility issue coming from
    /// system and build toolchain differences. OP-TEE OS only supports a single thread and
    /// thus does not explicitly set up the TLS area. In contrast, we do use an x86 toolchain to
    /// compile OP-TEE TAs and this toolchain assumes there is a valid TLS areas for various purposes
    /// including stack protection. To this end, the toolchain generates binaries using
    /// the `FS` register for TLS access.
    /// This function allocates a TLS area on behalf of the TA to satisfy the toolchain's assumption.
    /// Instead of using this function, we could change the flags of the toolchain to not use TLS
    /// (e.g., `-fno-stack-protector`), but this might be insecure. Also, the toolchain might have
    /// other features relying on TLS.
    #[cfg(target_arch = "x86_64")]
    fn allocate_guest_tls(
        &self,
        tls_size: Option<usize>,
    ) -> Result<(), litebox_common_linux::errno::Errno> {
        let tls_size = tls_size.unwrap_or(PAGE_SIZE).next_multiple_of(PAGE_SIZE);
        let addr = self.sys_mmap(
            0,
            tls_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_POPULATE,
            -1,
            0,
        )?;
        // Store TLS address for later restoration
        self.tls_base_addr.set(addr.as_usize());
        self.restore_guest_tls();
        Ok(())
    }

    /// Restore the guest TLS (FS base) before entering the TA.
    ///
    /// FS base is cleared across VTL switches, so we must restore it before
    /// every TA entry.
    #[cfg(target_arch = "x86_64")]
    fn restore_guest_tls(&self) {
        let addr = self.tls_base_addr.get();
        if addr == 0 {
            return; // TLS not allocated yet
        }
        let punchthrough = litebox_common_linux::PunchthroughSyscall::SetFsBase { addr };
        let token = litebox_platform_multiplex::platform()
            .get_punchthrough_token_for(punchthrough)
            .expect("Failed to get punchthrough token for SET_FS");
        let _ = token.execute().map(|_| ()).map_err(|e| match e {
            litebox::platform::PunchthroughError::Failure(errno) => errno,
            _ => unimplemented!("Unsupported punchthrough error {:?}", e),
        });
    }

    /// Retrieve the result of the `ldelf` execution.
    fn get_ldelf_result(&self) {
        let ldelf_arg_address = match self.thread.init_state.get() {
            ThreadInitState::Ldelf {
                ldelf_arg_address, ..
            } => Some(ldelf_arg_address),
            _ => None,
        };
        if let Some(ldelf_arg_address) = ldelf_arg_address {
            let ldelf_arg_ptr = UserConstPtr::<LdelfArg>::from_usize(ldelf_arg_address);
            if let Some(ldef_arg) = ldelf_arg_ptr.read_at_offset(0) {
                let entry_func = usize::try_from(ldef_arg.entry_func).unwrap();
                // If `ldelf` has been successfully executed, it loads the given TA and stores the TA's entry
                // point into `ldelf_arg.entry_func`.
                self.set_ta_entry_point(entry_func);
            }
        }
        // Note: `ldelf` allocates stack (returned via `ldelf_arg_out.stack_ptr`) but we don't use it.
        // Need to revisit this to see whether the stack is large enough for our use cases (e.g.,
        // copy owned data through stack to minimize TOCTTOU threats).
    }

    /// Set the base address of the TA stack for the current task.
    ///
    /// The TA stack base is provided by LiteBox and trusted.
    pub(crate) fn set_ta_stack_base_addr(&self, addr: usize) {
        self.ta_stack_base_addr.set(addr);
    }

    /// Get the base address of the TA stack for the current task.
    pub(crate) fn get_ta_stack_base_addr(&self) -> Option<usize> {
        let addr = self.ta_stack_base_addr.get();
        if addr == 0 { None } else { Some(addr) }
    }

    /// Set the entry point of the TA for the current task.
    ///
    /// Since the TA entry point is provided by `ldelf` which is untrusted, we checks whether
    /// the given `addr` is within the user space.
    pub(crate) fn set_ta_entry_point(&self, addr: usize) {
        let ptr = UserConstPtr::<u8>::from_usize(addr);
        if ptr.read_at_offset(0).is_some() {
            self.ta_entry_point.set(addr);
        }
    }

    /// Get the entry point of the TA for the current task.
    pub(crate) fn get_ta_entry_point(&self) -> usize {
        self.ta_entry_point.get()
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
    if let Some(src_slice) = src.to_owned_slice(src_len)
        && let Some(length) = dst_len.read_at_offset(0)
        && usize::try_from(length).unwrap() <= MAX_KERNEL_BUF_SIZE
    {
        let mut length = usize::try_from(length).unwrap();
        let mut kernel_buf = vec![0u8; length];
        syscall_fn(task, state, &src_slice, &mut kernel_buf, &mut length).and_then(|()| {
            let _ = dst_len.write_at_offset(0, u64::try_from(length).unwrap());
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
        Self {
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
        Self {
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
                    let key_addr: usize = user_attrs[0].a.truncate();
                    let key_len = usize::try_from(user_attrs[0].b).unwrap();
                    // TODO: revisit buffer size limits based on OP-TEE spec and deployment constraints
                    if key_len > MAX_KERNEL_BUF_SIZE {
                        return Err(TeeResult::BadParameters);
                    }
                    let key_ptr = UserConstPtr::<u8>::from_usize(key_addr);
                    let key_slice = key_ptr
                        .to_owned_slice(key_len)
                        .ok_or(TeeResult::BadParameters)?;
                    tee_obj.set_key(&key_slice);
                }
                _ => todo!(
                    "handle attribute ID: {}",
                    user_attrs[0].attribute_id.value()
                ),
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
        Self {
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
        Self {
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

/// Entry in the TA UUID map containing binary data and parsed flags.
struct TaInfo {
    /// The raw TA binary
    binary: alloc::boxed::Box<[u8]>,
    /// Parsed TA flags from .ta_head section
    flags: TaFlags,
}

/// Data structure to maintain a mapping from TA UUIDs to their binary data and flags.
pub(crate) struct TaUuidMap {
    inner: spin::mutex::SpinMutex<HashMap<TeeUuid, TaInfo>>,
}

impl TaUuidMap {
    pub(crate) fn new() -> Self {
        Self {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub(crate) fn insert(&self, uuid: TeeUuid, ta_bin: alloc::boxed::Box<[u8]>) -> bool {
        // Parse TA head from the binary's .ta_head section
        let Some(ta_head) = litebox_common_optee::parse_ta_head(&ta_bin) else {
            return false;
        };

        // Verify that the TA binary's UUID matches the expected UUID
        if ta_head.uuid != uuid {
            return false;
        }

        let mut inner = self.inner.lock();
        inner.insert(
            uuid,
            TaInfo {
                binary: ta_bin,
                flags: ta_head.flags,
            },
        );
        true
    }

    pub(crate) fn get(&self, uuid: &TeeUuid) -> Option<alloc::boxed::Box<[u8]>> {
        self.inner.lock().get(uuid).map(|info| info.binary.clone())
    }

    /// Get the TA flags for a given UUID.
    pub(crate) fn get_flags(&self, uuid: &TeeUuid) -> Option<TaFlags> {
        self.inner.lock().get(uuid).map(|info| info.flags)
    }

    // Lazy removal of TA binaries when they are no longer needed.
    pub(crate) fn remove(&self, uuid: &TeeUuid) -> Option<alloc::boxed::Box<[u8]>> {
        self.inner.lock().remove(uuid).map(|info| info.binary)
    }
}

/// TA/session-related information for the current task
struct Task {
    global: Arc<GlobalState>,
    thread: ThreadState,
    /// Session ID
    session_id: u32,
    /// TA UUID
    ta_app_id: TeeUuid,
    /// Client identity (VTL0 process or another TA)
    client_identity: TeeIdentity,
    /// TEE cryptography state map
    tee_cryp_state_map: TeeCrypStateMap,
    /// TEE object map
    tee_obj_map: TeeObjMap,
    /// TA handle to UUID map
    ta_handle_map: TaHandleMap,
    /// TA entry point
    ta_entry_point: Cell<usize>,
    /// TA stack base address
    ta_stack_base_addr: Cell<usize>,
    /// Whether the TA has been prepared
    ta_prepared: Cell<bool>,
    /// TLS base address for x86_64 (stored to restore FS before each TA entry)
    #[cfg(target_arch = "x86_64")]
    tls_base_addr: Cell<usize>,
    // TODO: OP-TEE supports global, persistent objects across sessions. Add these maps if needed.
}

impl Drop for Task {
    fn drop(&mut self) {
        SessionIdPool::recycle(self.session_id);
    }
}

struct ThreadState {
    init_state: Cell<ThreadInitState>,
    /// Whether init has been called. This is used to ensure `handle_init_request`
    /// is invoked at most once.
    initialized: Cell<bool>,
}

impl ThreadState {
    pub fn new() -> Self {
        Self {
            init_state: Cell::new(ThreadInitState::None),
            initialized: Cell::new(false),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) enum ThreadInitState {
    #[default]
    None,
    Ldelf {
        ldelf_arg_address: usize,
        entry_point: usize,
        stack_top: usize,
    },
    Ta {
        cmd_id: usize,
        params_address: usize,
        session_id: usize,
        func_id: usize,
        entry_point: usize,
        stack_top: usize,
    },
}

/// Global session ID pool (Linux pidmap style).
///
/// Uses spinlock-protected bitmap for recyclable IDs (1..=MAX_RECYCLABLE_SESSION_ID),
/// with fallback to one-time IDs beyond that range.
///
/// With MAX_RECYCLABLE_SESSION_ID = 65535:
/// - Bitmap memory usage: (65535 + 1) bits = 8 KB
/// - Recyclable IDs: 1..=65535 (65535 IDs)
/// - Fallback (non-recyclable) IDs: 65536..=0xffff_fffd (~4.3B IDs, excluding PTA_SESSION_ID)
/// - PTA_SESSION_ID (0xffff_fffe) is reserved and never allocated
///
/// Design notes:
/// - A single TA instance can serve many concurrent sessions (no per-instance cap),
///   so the bitmap must cover realistic peak concurrency.
/// - Allocation uses `last_id` as a hint for O(1) amortized scans; worst-case O(n)
///   full scan only occurs when the bitmap is nearly full.
/// - 8 KB is modest for the secure world (with a small amount of memory) and avoids falling
///   into the non-recyclable fallback path under normal workloads. Fallback IDs are
///   a one-way leak (never recycled).
pub(crate) struct SessionIdPool {
    bitmap: bitvec::vec::BitVec, // bit[id] set = in use; bit 0 unused (session ID 0 is invalid)
    last_id: u32,                // for wrap-around scanning
    fallback_next: u32,          // one-time IDs when bitmap exhausted
}

fn session_id_pool() -> &'static spin::mutex::SpinMutex<SessionIdPool> {
    static POOL: spin::once::Once<spin::mutex::SpinMutex<SessionIdPool>> = spin::once::Once::new();
    POOL.call_once(|| {
        spin::mutex::SpinMutex::new(SessionIdPool {
            bitmap: bitvec::bitvec![0; SessionIdPool::MAX_RECYCLABLE_SESSION_ID as usize + 1],
            last_id: 0,
            fallback_next: SessionIdPool::MAX_RECYCLABLE_SESSION_ID + 1,
        })
    })
}

impl SessionIdPool {
    /// Maximum recyclable session ID tracked by the bitmap.
    const MAX_RECYCLABLE_SESSION_ID: u32 = 65535;
    /// Reserved session ID for PTA.
    const PTA_SESSION_ID: u32 = 0xffff_fffe;

    /// Allocate a new session ID.
    ///
    /// Returns `None` if all recyclable session IDs are currently in use and
    /// the fallback one-time IDs are exhausted.
    pub fn allocate() -> Option<u32> {
        let mut pool = session_id_pool().lock();

        let start = if pool.last_id >= Self::MAX_RECYCLABLE_SESSION_ID {
            1
        } else {
            pool.last_id + 1
        };

        for id in (start..=Self::MAX_RECYCLABLE_SESSION_ID).chain(1..start) {
            if !pool.bitmap[id as usize] {
                pool.bitmap.set(id as usize, true);
                pool.last_id = id;
                return Some(id);
            }
        }

        // Bitmap exhausted - use fallback one-time IDs if available
        let fallback_id = pool.fallback_next;
        if fallback_id >= Self::PTA_SESSION_ID {
            return None;
        }
        pool.fallback_next = fallback_id + 1;
        Some(fallback_id)
    }

    /// Recycle a session ID for reuse. Fallback IDs are not recycled.
    pub fn recycle(session_id: u32) {
        if session_id == 0 || session_id > Self::MAX_RECYCLABLE_SESSION_ID {
            return;
        }

        let mut pool = session_id_pool().lock();
        pool.bitmap.set(session_id as usize, false);
    }

    pub fn get_pta_session_id() -> u32 {
        Self::PTA_SESSION_ID
    }
}

pub type NormalWorldConstPtr<T, const ALIGN: usize> = crate::ptr::PhysConstPtr<T, ALIGN>;
pub type NormalWorldMutPtr<T, const ALIGN: usize> = crate::ptr::PhysMutPtr<T, ALIGN>;

#[cfg(test)]
mod test_utils {
    use super::*;

    impl GlobalState {
        /// Make a new task with default values for testing.
        pub(crate) fn new_test_task(self: Arc<Self>) -> Task {
            Task {
                global: self.clone(),
                thread: ThreadState::new(),
                session_id: SessionIdPool::allocate().unwrap(),
                ta_app_id: TeeUuid::default(),
                client_identity: TeeIdentity {
                    login: TeeLogin::User,
                    uuid: TeeUuid::default(),
                },
                tee_cryp_state_map: TeeCrypStateMap::new(),
                tee_obj_map: TeeObjMap::new(),
                ta_handle_map: TaHandleMap::new(),
                ta_entry_point: Cell::new(0),
                ta_stack_base_addr: Cell::new(0),
                ta_prepared: Cell::new(false),
                #[cfg(target_arch = "x86_64")]
                tls_base_addr: Cell::new(0),
            }
        }
    }
}

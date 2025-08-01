//! A shim that provides an OP-TEE-compatible ABI via LiteBox

#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

// TODO(jayb) Replace out all uses of once_cell and such with our own implementation that uses
// platform-specific things within it.
use once_cell::race::OnceBox;

use alloc::{collections::vec_deque::VecDeque, vec};
use hashbrown::HashMap;
use litebox::{
    LiteBox,
    mm::{PageManager, linux::PAGE_SIZE},
    platform::{RawConstPointer as _, RawMutPointer as _, ThreadProvider as _},
};
use litebox_common_optee::{SyscallRequest, TeeResult, UteeEntryFunc, UteeParams};
use litebox_platform_multiplex::Platform;

use crate::loader::elf::ElfLoadInfo;

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
type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

/// Handle OP-TEE syscalls
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development purposes.
pub fn handle_syscall_request(request: SyscallRequest<Platform>) -> u32 {
    let res: Result<(), TeeResult> = match request {
        SyscallRequest::Return { ret } => syscalls::tee::sys_return(ret),
        SyscallRequest::Log { buf, len } => match unsafe { buf.to_cow_slice(len) } {
            Some(buf) => syscalls::tee::sys_log(&buf),
            None => Err(TeeResult::BadParameters),
        },
        SyscallRequest::Panic { code } => syscalls::tee::sys_panic(code),
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

pub(crate) struct SessionIdElfLoadInfoMap {
    inner: spin::mutex::SpinMutex<HashMap<u32, ElfLoadInfo>>,
}

impl SessionIdElfLoadInfoMap {
    pub fn new() -> Self {
        SessionIdElfLoadInfoMap {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, session_id: u32, elf_load_info: &ElfLoadInfo) {
        self.inner.lock().insert(session_id, *elf_load_info);
    }

    pub fn get(&self, session_id: u32) -> Option<ElfLoadInfo> {
        self.inner.lock().get(&session_id).copied()
    }

    pub fn remove(&self, session_id: u32) {
        self.inner.lock().remove(&session_id);
    }
}

fn session_id_elf_load_info_map() -> &'static SessionIdElfLoadInfoMap {
    static SESS_ID_ELF_LOAD_INFO_MAP: OnceBox<SessionIdElfLoadInfoMap> = OnceBox::new();
    SESS_ID_ELF_LOAD_INFO_MAP.get_or_init(|| alloc::boxed::Box::new(SessionIdElfLoadInfoMap::new()))
}

pub fn add_session_id_elf_load_info(session_id: u32, elf_load_info: &ElfLoadInfo) {
    session_id_elf_load_info_map().insert(session_id, elf_load_info);
}

#[derive(Clone, Copy)]
pub(crate) struct OpteeCommand {
    pub func: UteeEntryFunc,
    pub params: UteeParams,
    pub cmd_id: u32,
}

pub(crate) struct OpteeCommandQueue {
    inner: spin::mutex::SpinMutex<HashMap<u32, VecDeque<OpteeCommand>>>,
}

impl OpteeCommandQueue {
    pub fn new() -> Self {
        OpteeCommandQueue {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn push(&self, session_id: u32, cmd: &OpteeCommand) {
        self.inner
            .lock()
            .entry(session_id)
            .or_default()
            .push_back(*cmd);
    }

    pub fn pop(&self, session_id: u32) -> Option<OpteeCommand> {
        self.inner
            .lock()
            .get_mut(&session_id)
            .and_then(alloc::collections::VecDeque::pop_front)
    }

    pub fn remove(&self, session_id: u32) {
        self.inner.lock().remove(&session_id);
    }
}

pub(crate) fn optee_command_queue() -> &'static OpteeCommandQueue {
    static QUEUE: OnceBox<OpteeCommandQueue> = OnceBox::new();
    QUEUE.get_or_init(|| alloc::boxed::Box::new(OpteeCommandQueue::new()))
}

pub fn add_optee_command(session_id: u32, func: UteeEntryFunc, params: &UteeParams, cmd_id: u32) {
    let cmd = OpteeCommand {
        func,
        params: *params,
        cmd_id,
    };
    optee_command_queue().push(session_id, &cmd);
}

pub fn optee_command_loop() -> ! {
    if let Some(cmd) = optee_command_queue().pop(1) {
        let elf_load_info = session_id_elf_load_info_map().get(1);
        let Some(elf_load_info) = elf_load_info else {
            litebox_platform_multiplex::platform().terminate_thread(0);
        };
        let params =
            unsafe { &mut *(elf_load_info.params_address as *mut usize).cast::<UteeParams>() };
        *params = cmd.params;

        unsafe {
            jump_to_entry_point(
                cmd.func as u32 as usize,
                1,
                elf_load_info.params_address,
                cmd.cmd_id as usize,
                elf_load_info.entry_point,
                elf_load_info.user_stack_top,
            );
        }
    } else {
        // no command left. terminate the thread for now (or sleep until next command comes)
        session_id_elf_load_info_map().remove(1);
        optee_command_queue().remove(1);
        litebox_platform_multiplex::platform().terminate_thread(0);
    }
}

/// TAs obtain four arguments through CPU registers:
/// - rdi: function ID
/// - rsi: session ID
/// - rdx: the address of parameters
/// - rcx: command ID
#[unsafe(naked)]
unsafe extern "C" fn jump_to_entry_point(
    func: usize,
    session_id: usize,
    params: usize,
    cmd_id: usize,
    entry_point: usize,
    user_stack_top: usize,
) -> ! {
    core::arch::naked_asm!("mov rsp, r9", "jmp r8", "hlt");
}

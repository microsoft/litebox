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
use litebox_common_optee::{SyscallRequest, TeeParamType, TeeResult, UteeEntryFunc, UteeParams};
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

/// Maintain ELF load information for each session ID
pub(crate) struct SessionIdElfLoadInfoMap {
    inner: spin::mutex::SpinMutex<HashMap<u32, ElfLoadInfo>>,
}

impl SessionIdElfLoadInfoMap {
    pub fn new() -> Self {
        SessionIdElfLoadInfoMap {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, session_id: u32, elf_load_info: ElfLoadInfo) {
        self.inner.lock().insert(session_id, elf_load_info);
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

/// Register ELF load information for a session ID
pub fn register_session_id_elf_load_info(session_id: u32, elf_load_info: ElfLoadInfo) {
    session_id_elf_load_info_map().insert(session_id, elf_load_info);
}

/// OP-TEE TA command structure for the command submission queue
#[derive(Clone)]
pub(crate) struct OpteeCommand {
    pub func: UteeEntryFunc,
    pub params: [UteeParamsTyped; UteeParamsTyped::TEE_NUM_PARAMS],
    pub cmd_id: u32,
}

/// Typed `UteeParams` for OP-TEE commands
#[derive(Clone)]
pub enum UteeParamsTyped {
    None,
    ValueInput {
        value_a: u64,
        value_b: u64,
    },
    ValueOutput {},
    ValueInout {
        value_a: u64,
        value_b: u64,
    },
    MemrefInput {
        data: alloc::vec::Vec<u8>,
    },
    MemrefOutput {
        buffer_size: usize,
    },
    MemrefInout {
        data: alloc::vec::Vec<u8>,
        buffer_size: usize,
    },
}

impl UteeParamsTyped {
    pub const TEE_NUM_PARAMS: usize = UteeParams::TEE_NUM_PARAMS;
}

/// OP-TEE command submission queue
pub(crate) struct OpteeCommandQueue {
    inner: spin::mutex::SpinMutex<HashMap<u32, VecDeque<OpteeCommand>>>,
}

impl OpteeCommandQueue {
    pub fn new() -> Self {
        OpteeCommandQueue {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn push(&self, session_id: u32, cmd: OpteeCommand) {
        self.inner
            .lock()
            .entry(session_id)
            .or_default()
            .push_back(cmd);
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

/// OP-TEE command completion queue which stores the addresses of `UteeParams`
pub(crate) struct OpteeResultQueue {
    inner: spin::mutex::SpinMutex<HashMap<u32, VecDeque<usize>>>,
}

impl OpteeResultQueue {
    pub fn new() -> Self {
        OpteeResultQueue {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn push(&self, session_id: u32, result: usize) {
        self.inner
            .lock()
            .entry(session_id)
            .or_default()
            .push_back(result);
    }

    pub fn pop(&self, session_id: u32) -> Option<usize> {
        self.inner
            .lock()
            .get_mut(&session_id)
            .and_then(alloc::collections::VecDeque::pop_front)
    }

    pub fn remove(&self, session_id: u32) {
        self.inner.lock().remove(&session_id);
    }
}

pub(crate) fn optee_command_submission_queue() -> &'static OpteeCommandQueue {
    static QUEUE: OnceBox<OpteeCommandQueue> = OnceBox::new();
    QUEUE.get_or_init(|| alloc::boxed::Box::new(OpteeCommandQueue::new()))
}

pub(crate) fn optee_command_completion_queue() -> &'static OpteeResultQueue {
    static COMPLETE_QUEUE: OnceBox<OpteeResultQueue> = OnceBox::new();
    COMPLETE_QUEUE.get_or_init(|| alloc::boxed::Box::new(OpteeResultQueue::new()))
}

/// Push or enqueue an OP-TEE command to the command queue which will be
/// consumed by `optee_command_loop`.
pub fn submit_optee_command(
    session_id: u32,
    func: UteeEntryFunc,
    params: [UteeParamsTyped; UteeParamsTyped::TEE_NUM_PARAMS],
    cmd_id: u32,
) {
    let cmd = OpteeCommand {
        func,
        params,
        cmd_id,
    };
    optee_command_submission_queue().push(session_id, cmd);
}

/// OP-TEE command loop that dequeues commands from the command queue and handles each of them
/// by interacting with loaded TAs.
/// For now, it terminates the thread if there is no commands left in the queue.
/// Instead, it can be an infinite loop with sleep to continously handle commands
/// (i.e., `UteeEntryFunc::InvokeCommand`) until it gets `UteeEntryFunc::CloseSession`
/// from the queue.
/// # Panics
/// This function panics if it cannot allocate a stack
pub fn optee_command_loop() -> ! {
    let session_id = 1; // For now, we only support a single session ID (1).

    if let Some(cmd) = optee_command_submission_queue().pop(session_id) {
        let elf_load_info = session_id_elf_load_info_map().get(session_id);
        let Some(elf_load_info) = elf_load_info else {
            litebox_platform_multiplex::platform().terminate_thread(0);
        };

        // In OP-TEE TA, each command invocation is like (re)starting the TA with a new stack with
        // loaded binary and heap. In that sense, we can create (and destroy) a stack
        // for each command freely.
        let mut stack = crate::loader::ta_stack::allocate_stack().unwrap_or_else(|| {
            panic!("Failed to allocate stack for session ID: {}", session_id);
        });
        stack
            .init(cmd.params.as_slice())
            .expect("Failed to initialize stack with parameters");

        optee_command_completion_queue().push(session_id, stack.get_params_address());

        unsafe {
            jump_to_entry_point(
                cmd.func as u32 as usize,
                session_id as usize,
                stack.get_params_address(),
                cmd.cmd_id as usize,
                elf_load_info.entry_point,
                stack.get_cur_stack_top(),
            );
        }
    } else {
        while let Some(result) = optee_command_completion_queue().pop(session_id) {
            let params = unsafe { &*(result as *const UteeParams) };
            for idx in 0..UteeParams::TEE_NUM_PARAMS {
                let param_type = params.get_type(idx).expect("Failed to get parameter type");
                match param_type {
                    TeeParamType::ValueOutput | TeeParamType::ValueInout => {
                        if let Ok(Some((value_a, value_b))) = params.get_values(idx) {
                            #[cfg(debug_assertions)]
                            litebox::log_println!(
                                litebox_platform_multiplex::platform(),
                                "output (index: {}): {:#x} {:#x}",
                                idx,
                                value_a,
                                value_b,
                            );
                            // TODO: return the outcome
                        }
                    }
                    TeeParamType::MemrefOutput | TeeParamType::MemrefInout => {
                        if let Ok(Some((addr, len))) = params.get_values(idx) {
                            let slice = unsafe {
                                &*core::ptr::slice_from_raw_parts(
                                    addr as *const u8,
                                    usize::try_from(len).unwrap_or(0),
                                )
                            };
                            #[cfg(debug_assertions)]
                            litebox::log_println!(
                                litebox_platform_multiplex::platform(),
                                "output (index: {}): {:#x} {:?}",
                                idx,
                                addr,
                                slice,
                            );
                            // TODO: return the outcome
                        }
                    }
                    _ => {}
                }
            }
            // deallocate the stack here?
        }

        // no command left. terminate the thread for now (or sleep until next command comes)
        session_id_elf_load_info_map().remove(session_id);
        optee_command_submission_queue().remove(session_id);
        optee_command_completion_queue().remove(session_id);
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

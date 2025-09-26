//! OP-TEE Implementation for [`litebox_runner_command_dispatcher`]
extern crate alloc;

use hashbrown::HashMap;
use litebox::platform::ThreadProvider;
use litebox_common_optee::{TeeParamType, UteeParams};
use litebox_shim_optee::loader::ElfLoadInfo;
use once_cell::race::OnceBox;

/// Data structure to maintain a mapping from session IDs to ELF load information.
/// This is mainly for reentering TAs, where we need to know the entry point (and
/// stack base to reuse the already allocated stack).
/// TODO: We can store this information in the LiteBox TLS if we extend it (Linux
/// does not maintain the entry point of a program).
pub(crate) struct SessionIdElfLoadInfoMap {
    inner: spin::mutex::SpinMutex<HashMap<u32, ElfLoadInfo>>,
}

impl SessionIdElfLoadInfoMap {
    pub fn new() -> Self {
        SessionIdElfLoadInfoMap {
            inner: spin::mutex::SpinMutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, session_id: u32, elf_load_info: ElfLoadInfo) -> bool {
        let mut inner = self.inner.lock();
        if inner.contains_key(&session_id) {
            false
        } else {
            inner.insert(session_id, elf_load_info);
            true
        }
    }

    pub fn get(&self, session_id: u32) -> Option<ElfLoadInfo> {
        self.inner.lock().get(&session_id).copied()
    }

    pub fn remove(&self, session_id: u32) {
        self.inner.lock().remove(&session_id);
    }
}

pub fn session_id_elf_load_info_map() -> &'static SessionIdElfLoadInfoMap {
    static SESS_ID_ELF_LOAD_INFO_MAP: OnceBox<SessionIdElfLoadInfoMap> = OnceBox::new();
    SESS_ID_ELF_LOAD_INFO_MAP.get_or_init(|| alloc::boxed::Box::new(SessionIdElfLoadInfoMap::new()))
}

/// Register ELF load information for a session ID
pub fn register_session_id_elf_load_info(session_id: u32, elf_load_info: ElfLoadInfo) -> bool {
    session_id_elf_load_info_map().insert(session_id, elf_load_info)
}

/// A function to handle an OP-TEE TA command. This function sets up the stack and input `UteeParams`, and
/// jumps to the entry point of the TA.
pub fn optee_ta_command_handler(command: &litebox_runner_command_dispatcher::OpteeTaCommand) -> ! {
    let elf_load_info = session_id_elf_load_info_map().get(command.session_id);
    let Some(elf_load_info) = elf_load_info else {
        litebox_platform_multiplex::platform().terminate_thread(0);
    };

    // In OP-TEE TA, each command invocation is like (re)starting the TA with a new stack with
    // loaded binary and heap. In that sense, we can create (and destroy) a stack
    // for each command freely.
    let stack = litebox_shim_optee::loader::init_stack(
        Some(elf_load_info.stack_base),
        command.params.as_slice(),
    )
    .expect("Failed to initialize stack with parameters");

    unsafe {
        litebox_common_linux::swap_fsgs();
        jump_to_entry_point(
            command.func as u32 as usize,
            command.session_id as usize,
            stack.get_params_address(),
            command.cmd_id as usize,
            elf_load_info.entry_point,
            stack.get_cur_stack_top(),
        );
    }
}

/// TAs obtain four arguments through CPU registers:
/// - rdi: function ID
/// - rsi: session ID
/// - rdx: the address of parameters
/// - rcx: command ID
///
/// Extra two arguments: r8 (entry point) and r9 (user RSP)
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

/// A function to retrieve the results of the OP-TEE TA command execution.
/// This function is expected to be called through the OP-TEE TA command dispatcher's
/// return function once the TA has processed a command.
pub fn handle_optee_command_output(session_id: u32) {
    // TA stores results in the `UteeParams` structure and/or buffers it refers to.
    if let Some(elf_load_info) = session_id_elf_load_info_map().get(session_id) {
        let params = unsafe { &*(elf_load_info.params_address as *const UteeParams) };
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
                            slice
                        );
                        // TODO: return the outcome
                    }
                }
                _ => {}
            }
        }
    } else {
        panic!("No ELF load info found");
    }
}

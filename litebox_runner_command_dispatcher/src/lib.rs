//! An interface crate to expose command dispatching functionalities to
//! other crates (e.g., Shims) without worrying about dependency cycles.

#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use litebox_common_linux::errno::Errno;
use litebox_common_lvbs::VsmFunction;
use litebox_common_optee::{OpteeSmcFunction, UteeParamOwned};
use once_cell::race::OnceBox;

/// OP-TEE TA command representation. This command is delivered to a TA
/// through its entry point function and `libutee`.
pub enum OpteeTaCommand {
    /// Open a new session with a loaded TA. This lets the TA know
    /// its session ID and provides the parameters for the initialization.
    OpenSession {
        session_id: u32,
        params: Box<[UteeParamOwned; UteeParamOwned::TEE_NUM_PARAMS]>,
    },
    /// Close an existing session with a loaded TA.
    CloseSession { session_id: u32 },
    /// Invoke a command within an existing session with a loaded TA.
    InvokeCommand {
        session_id: u32,
        params: Box<[UteeParamOwned; UteeParamOwned::TEE_NUM_PARAMS]>,
        cmd_id: u32,
    },
}

// TODO: use enum to strongly type the commands
pub struct OpteeSmcCommand {
    pub func: OpteeSmcFunction,
    pub params: Box<[u64; OpteeSmcFunction::NUM_OPTEE_SMC_ARGS - 1]>,
}

// TODO: use enum to strongly type the commands
pub struct VsmVtlCommand {
    pub func: VsmFunction,
    pub params: Box<[u64; VsmFunction::NUM_VTLCALL_PARAMS - 1]>,
}

pub type OpteeTaCommandHandler = fn(&OpteeTaCommand) -> !;
pub type OpteeSmcCommandHandler = fn(&OpteeSmcCommand) -> Result<i64, Errno>;
pub type VsmVtlCommandHandler = fn(&VsmVtlCommand) -> Result<i64, Errno>;
pub type ReturnFunction = fn() -> !;

/// A command dispatcher to dispatch commands to appropriate handlers.
/// This runner currently only supports OP-TEE TA commands but other runners
/// (e.g., the LVBS runner) can support other commands types like
/// OP-TEE SMC commands and VSM-VTL Call commands.
pub struct CommandDispatcher {
    /// OP-TEE TA command handler function
    optee_ta_command_handler_fn: OnceBox<OpteeTaCommandHandler>,
    /// OP-TEE SMC command handler function
    optee_smc_command_handler_fn: OnceBox<OpteeSmcCommandHandler>,
    /// VSM VTL call command handler function
    vsm_vtl_command_handler_fn: OnceBox<VsmVtlCommandHandler>,
    /// Function to return from the handler
    return_function: OnceBox<ReturnFunction>,
}

impl CommandDispatcher {
    pub fn new() -> Self {
        Self {
            optee_ta_command_handler_fn: OnceBox::new(),
            optee_smc_command_handler_fn: OnceBox::new(),
            vsm_vtl_command_handler_fn: OnceBox::new(),
            return_function: OnceBox::new(),
        }
    }

    /// Register a command handler function for OP-TEE TA commands.
    pub fn register_optee_ta_command_handler(&self, handler: OpteeTaCommandHandler) {
        let _ = self.optee_ta_command_handler_fn.set(Box::new(handler));
    }

    /// Register a command handler function for OP-TEE SMC commands.
    pub fn register_optee_smc_command_handler(&self, handler: OpteeSmcCommandHandler) {
        let _ = self.optee_smc_command_handler_fn.set(Box::new(handler));
    }

    /// Register a command handler function for VSM VTL calls.
    pub fn register_vsm_vtl_command_handler(&self, handler: VsmVtlCommandHandler) {
        let _ = self.vsm_vtl_command_handler_fn.set(Box::new(handler));
    }

    /// Register a function to return from a command handler
    pub fn register_return_function(&self, function: ReturnFunction) {
        let _ = self.return_function.set(Box::new(function));
    }

    /// Call the registered OP-TEE TA command handler function.
    /// # Panics
    /// Panics if the command dispatcher function is not registered.
    pub fn handle_optee_ta_command(&self, command: &OpteeTaCommand) -> ! {
        if let Some(handler) = self.optee_ta_command_handler_fn.get() {
            (handler)(command)
        } else {
            panic!("OP-TEE command dispatcher not registered");
        }
    }

    /// Invoke the registered function to return from a command handler.
    /// We expect the command handler will eventually call this function regardless of
    /// whether the command processing was successful or failed.
    /// # Panics
    /// Panics if the return function is not registered.
    pub fn return_to_command_dispatcher(&self) -> ! {
        if let Some(return_function) = self.return_function.get() {
            (return_function)()
        } else {
            panic!("Return function not registered");
        }
    }

    /// Call the registered OP-TEE SMC command handler function.
    /// # Panics
    /// Panics if the command dispatcher function is not registered.
    pub fn handle_optee_smc_command(&self, command: &OpteeSmcCommand) -> Result<i64, Errno> {
        if let Some(handler) = self.optee_smc_command_handler_fn.get() {
            (handler)(command)
        } else {
            panic!("OP-TEE SMC command dispatcher not registered");
        }
    }

    /// Call the registered VSM VTL call command handler function.
    /// # Panics
    /// Panics if the command dispatcher function is not registered.
    pub fn handle_vsm_vtl_command(&self, command: &VsmVtlCommand) -> Result<i64, Errno> {
        if let Some(handler) = self.vsm_vtl_command_handler_fn.get() {
            (handler)(command)
        } else {
            panic!("VSM VTL call command dispatcher not registered");
        }
    }
}

impl Default for CommandDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Instantiate a global CommandDispatcher
pub fn command_dispatcher<'a>() -> &'a CommandDispatcher {
    static COMMAND_DISPATCHER: OnceBox<CommandDispatcher> = OnceBox::new();
    COMMAND_DISPATCHER.get_or_init(|| {
        let dispatcher = CommandDispatcher::new();
        Box::new(dispatcher)
    })
}

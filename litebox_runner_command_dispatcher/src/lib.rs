//! An interface crate to expose command dispatching functionalities to
//! other crates (e.g., Shims) without worrying about dependency cycles.

#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use litebox_common_optee::{UteeEntryFunc, UteeParamOwned};
use once_cell::race::OnceBox;

pub struct OpteeTaCommand {
    pub session_id: u32,
    pub func: UteeEntryFunc,
    pub params: Box<[UteeParamOwned; UteeParamOwned::TEE_NUM_PARAMS]>,
    pub cmd_id: u32,
}

pub type OpteeTaCommandHandler = fn(&OpteeTaCommand) -> !;
pub type ReturnFunction = fn() -> !;

/// A command dispatcher to dispatch commands to appropriate handlers.
/// This runner currently only supports OP-TEE TA commands but other runners
/// (e.g., the LVBS runner) can support other commands types like
/// OP-TEE SMC commands and VSM-VTL Call commands.
pub struct CommandDispatcher {
    /// OP-TEE TA command handler function
    optee_ta_command_handler_fn: OnceBox<OpteeTaCommandHandler>,
    /// Function to return from the handler
    return_function: OnceBox<ReturnFunction>,
}

impl CommandDispatcher {
    pub fn new() -> Self {
        Self {
            optee_ta_command_handler_fn: OnceBox::new(),
            return_function: OnceBox::new(),
        }
    }

    /// Register a command handler function for OP-TEE TA commands.
    pub fn register_optee_ta_command_handler(&self, handler: OpteeTaCommandHandler) {
        let _ = self.optee_ta_command_handler_fn.set(Box::new(handler));
    }

    /// Register a function to return from a command handler to the client who
    /// has sent the command.
    pub fn register_return_function(&self, function: ReturnFunction) {
        let _ = self.return_function.set(Box::new(function));
    }

    /// Call the registered OP-TEE TA command handler function to handle a command.
    /// This function never returns as it jumps (`iretq` or `jmp`) to
    /// the entry point of the registered command handler function.
    /// # Panics
    /// Panics if the command dispatcher function is not registered.
    pub fn handle_optee_ta_command(&self, command: &OpteeTaCommand) -> ! {
        if let Some(handler) = self.optee_ta_command_handler_fn.get() {
            (handler)(command)
        } else {
            panic!("OP-TEE command dispatcher not registered");
        }
    }

    /// Invoke the registered function to return from a command handler to the client.
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

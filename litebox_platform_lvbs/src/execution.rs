// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform-supplied hooks around user execution, not a scheduler.

use litebox::shim::Exception;

/// Timer integration supplied explicitly by the runner when entering user code.
///
/// The platform owns initialization, the budget, interrupt registration,
/// kernel-mode interrupt handling, and the lifetime of an armed execution
/// window. Shared execution code does not automatically disarm on return:
/// a platform may bound a larger window spanning multiple user entries. The
/// runner must initialize the timer and install its IRQ entries on the current
/// CPU before passing it to user execution.
///
/// There is no implicit disabled implementation. A debugging runner that does
/// not provide a timer must make that choice explicitly in its implementation.
pub trait ExecutionTimer {
    /// Arm the current CPU's execution window. Must be idempotent while that
    /// window remains armed, so nested entries/reentries do not extend it.
    fn arm(&self);

    /// Called before forwarding a user-mode exception/interrupt to the shim.
    /// Ignore unrelated vectors. For this timer's interrupt, acknowledge it
    /// and perform platform bookkeeping. The shim receives the original
    /// exception unchanged; this hook does not schedule or switch tasks.
    /// Called with interrupts disabled and kernel GS active. Do not block or
    /// reenter user execution from this hook.
    fn on_user_exception(&self, exception: Exception);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
    use litebox_common_linux::PtRegs;

    #[derive(Debug, PartialEq)]
    enum Event {
        Arm,
        Timer(Exception),
        Shim(Exception, u32, usize, bool),
    }

    struct Recorder(RefCell<Vec<Event>>);

    impl ExecutionTimer for Recorder {
        fn arm(&self) {
            self.0.borrow_mut().push(Event::Arm);
        }
        fn on_user_exception(&self, exception: Exception) {
            self.0.borrow_mut().push(Event::Timer(exception));
        }
    }

    impl EnterShim for Recorder {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn syscall(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn exception(&self, _ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
            self.0.borrow_mut().push(Event::Shim(
                info.exception,
                info.error_code,
                info.cr2,
                info.kernel_mode,
            ));
            ContinueOperation::Terminate
        }
    }

    #[test]
    fn user_exception_notifies_timer_before_forwarding_unchanged_info() {
        // Deliberately not LVBS's vector: shared execution must not know it.
        let recorder = Recorder(RefCell::new(Vec::new()));
        let mut regs = PtRegs::default();
        let mut context = crate::ThreadContext::new(&recorder, &mut regs, &recorder);
        let info = ExceptionInfo {
            exception: Exception(0x51),
            error_code: 7,
            cr2: 0x1234,
            kernel_mode: false,
        };
        assert_eq!(
            context.handle_exception(&info),
            ContinueOperation::Terminate
        );
        assert_eq!(
            *recorder.0.borrow(),
            [
                Event::Arm,
                Event::Timer(info.exception),
                Event::Shim(info.exception, 7, 0x1234, false)
            ]
        );
    }

    #[test]
    fn kernel_fault_does_not_call_the_user_timer_hook() {
        let recorder = Recorder(RefCell::new(Vec::new()));
        let mut regs = PtRegs::default();
        let mut context = crate::ThreadContext::new(&recorder, &mut regs, &recorder);
        let info = ExceptionInfo {
            exception: Exception::PAGE_FAULT,
            error_code: 2,
            cr2: 0x4321,
            kernel_mode: true,
        };
        assert_eq!(
            context.handle_exception(&info),
            ContinueOperation::Terminate
        );
        assert_eq!(
            *recorder.0.borrow(),
            [Event::Arm, Event::Shim(info.exception, 2, 0x4321, true)]
        );
    }
}

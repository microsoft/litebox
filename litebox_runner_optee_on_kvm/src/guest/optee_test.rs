// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Real OP-TEE TA lifecycle test using the repository's unmodified ldelf and
//! hello TA fixtures. No transport: all inputs are value parameters owned here.

use super::{Platform as Kernel, console, optee_platform::OpteePlatform};
use alloc::boxed::Box;
use core::cell::Cell;
use litebox::{
    platform::RawConstPointer,
    shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo},
};
use litebox_common_linux::PtRegs;
use litebox_common_optee::{
    TeeIdentity, TeeLogin, TeeResult, TeeUuid, UteeEntryFunc, UteeParamOwned, UteeParams,
};
use litebox_platform_lvbs::{execution::ExecutionTimer, serial_println};
use litebox_shim_optee::{OpteeShimBuilder, UserConstPtr, session::SessionManager};

// Existing project test assets, with their existing BSD license/provenance.
// These are raw syscall binaries: unlike the userland runner, a guest kernel
// must not rewrite their syscall instructions.
const LDELF: &[u8] =
    include_bytes!("../../../litebox_runner_optee_on_linux_userland/tests/ldelf.elf");
const HELLO: &[u8] =
    include_bytes!("../../../litebox_runner_optee_on_linux_userland/tests/hello-ta.elf");
const HELLO_3SEG: &[u8] =
    include_bytes!("../../../litebox_runner_optee_on_linux_userland/tests/hello3seg-ta.elf");

/// No timer/scheduler in this debugging harness. These are trusted finite test
/// TAs; the CI host process timeout is mandatory and a timeout fails the test.
struct FiniteTestTimer;
impl ExecutionTimer for FiniteTestTimer {
    fn arm(&self) {}
    fn on_user_exception(&self, _exception: Exception) {}
}

/// Observe genuine shim dispatch, never fabricate results or replace handlers.
struct Observed<'a, T> {
    inner: &'a T,
    syscalls: Cell<usize>,
    faults: Cell<usize>,
}
impl<T: EnterShim<ExecutionContext = PtRegs>> EnterShim for Observed<'_, T> {
    type ExecutionContext = PtRegs;
    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.inner.init(ctx)
    }
    fn reenter(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.inner.reenter(ctx)
    }
    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.syscalls.set(self.syscalls.get() + 1);
        self.inner.syscall(ctx)
    }
    fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
        self.faults.set(self.faults.get() + 1);
        self.inner.exception(ctx, info)
    }
    fn interrupt(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.inner.interrupt(ctx)
    }
}

pub(super) fn run(kernel: &'static Kernel) {
    // Shim APIs require static platform/session-manager references. Allocate
    // once for this VM test, not through a global singleton or registration.
    let platform = Box::leak(Box::new(OpteePlatform::new(kernel)));
    let sessions = Box::leak(Box::new(SessionManager::<OpteePlatform>::new()));
    for (name, binary) in [("hello", HELLO), ("hello3seg", HELLO_3SEG)] {
        serial_println!(console; "OPTEE-TEST: {name} begin");
        let task = kernel.create_task_page_table().unwrap();
        unsafe {
            kernel.switch_page_table(task).unwrap();
        }
        let shim = OpteeShimBuilder::new(platform, sessions).build();
        let uuid = litebox_common_optee::parse_ta_head(binary)
            .expect("invalid fixture TA header")
            .uuid;
        assert!(shim.store_ta_bin(&uuid, binary));
        // Keep the session token live through CloseSession; dropping afterward
        // recycles its ID and clears the identity. No global session registry.
        let token = sessions
            .try_acquire_open_session_token()
            .expect("session token");
        let session_id = token.session_id().unwrap();
        sessions.set_session_client_identity(
            session_id,
            Some(TeeIdentity {
                login: TeeLogin::User,
                uuid: TeeUuid::NIL,
            }),
        );
        let loaded = shim.load_ldelf(LDELF, uuid).expect("load ldelf fixture");
        let entrypoints = loaded.entrypoints.as_ref().unwrap();
        let observed = Observed {
            inner: entrypoints,
            syscalls: Cell::new(0),
            faults: Cell::new(0),
        };
        let mut ctx = PtRegs::default();
        unsafe {
            litebox_platform_lvbs::run_thread_ref(&observed, &mut ctx, &FiniteTestTimer);
        }
        assert_eq!(ctx.rax, 0, "{name}: ldelf/TA_CreateEntryPoint failed");
        assert!(
            observed.syscalls.get() > 0,
            "ldelf did not execute shim syscalls"
        );
        serial_println!(console; "OPTEE-TEST: {name} ldelf OK syscalls={}", observed.syscalls.get());

        let none = [const { UteeParamOwned::None }; 4];
        entrypoints
            .load_ta_context(&none, session_id, UteeEntryFunc::OpenSession as u32, None)
            .unwrap();
        let before = observed.syscalls.get();
        unsafe {
            litebox_platform_lvbs::reenter_thread_ref(&observed, &mut ctx, &FiniteTestTimer);
        }
        assert_eq!(ctx.rax, 0, "{name}: TA_OpenSessionEntryPoint failed");
        assert!(
            observed.syscalls.get() > before,
            "open session did not execute shim syscalls"
        );
        serial_println!(console; "OPTEE-TEST: {name} open-session OK");

        for (command, input, expected) in [(0, 100, 101), (1, 200, 199), (0, 41, 42)] {
            let params = [
                UteeParamOwned::ValueInout {
                    value_a: input,
                    value_b: 0,
                },
                UteeParamOwned::None,
                UteeParamOwned::None,
                UteeParamOwned::None,
            ];
            entrypoints
                .load_ta_context(
                    &params,
                    session_id,
                    UteeEntryFunc::InvokeCommand as u32,
                    Some(command),
                )
                .unwrap();
            let before = observed.syscalls.get();
            unsafe {
                litebox_platform_lvbs::reenter_thread_ref(&observed, &mut ctx, &FiniteTestTimer);
            }
            assert_eq!(ctx.rax, 0, "{name}: invoke {command} failed");
            assert!(observed.syscalls.get() > before);
            let output = UserConstPtr::<OpteePlatform, UteeParams>::from_usize(
                loaded.params_address.unwrap(),
            )
            .read_at_offset(0)
            .expect("read actual TA output params");
            assert_eq!(
                output.get_values(0).unwrap(),
                Some((expected, 0)),
                "{name}: wrong TA command output"
            );
            serial_println!(console; "OPTEE-TEST: {name} invoke cmd={command} input={input} output={expected} OK");
        }
        // Confirm real error propagation too: hello rejects unknown commands.
        entrypoints
            .load_ta_context(
                &none,
                session_id,
                UteeEntryFunc::InvokeCommand as u32,
                Some(99),
            )
            .unwrap();
        unsafe {
            litebox_platform_lvbs::reenter_thread_ref(&observed, &mut ctx, &FiniteTestTimer);
        }
        assert_eq!(
            ctx.rax,
            TeeResult::BadParameters as usize,
            "{name}: unknown command must fail"
        );
        serial_println!(console; "OPTEE-TEST: {name} invalid-command rejected OK");

        entrypoints
            .load_ta_context(&none, session_id, UteeEntryFunc::CloseSession as u32, None)
            .unwrap();
        let before = observed.syscalls.get();
        unsafe {
            litebox_platform_lvbs::reenter_thread_ref(&observed, &mut ctx, &FiniteTestTimer);
        }
        assert_eq!(ctx.rax, 0, "{name}: TA_CloseSessionEntryPoint failed");
        assert!(observed.syscalls.get() > before);
        serial_println!(console; "OPTEE-TEST: {name} close-session OK syscalls={} faults={}", observed.syscalls.get(), observed.faults.get());
        drop(loaded);
        drop(token);
        unsafe {
            shim.release_user_mappings();
            kernel
                .switch_page_table(litebox_platform_lvbs::BASE_PAGE_TABLE_ID)
                .unwrap();
            kernel.delete_task_page_table(task).unwrap();
        }
        drop(shim);
        serial_println!(console; "OPTEE-TEST: {name} PASS");
    }
    serial_println!(console; "OPTEE-TEST: PASS");
}

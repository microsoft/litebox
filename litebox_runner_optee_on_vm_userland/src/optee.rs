// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Serves entry requests for the process's one TA instance, in the message
//! format of [`litebox_common_optee::envelope`].
//!
//! Lockdown: after the broker connects, no new association and only
//! [`SERVING_BROKER_OPS`]; once the TA's code is mapped, or the first open
//! fails before that, and before the TA first runs, only [`SERVING_CALLS`] and
//! no new executable memory. The TA's code includes its syscall trampoline,
//! which the first TA context load maps.

use alloc::boxed::Box;
use core::cell::RefCell;
use core::ops::Range;
use litebox::platform::RawConstPointer as _;
use litebox::utils::TruncateExt as _;
use litebox_common_linux::PtRegs;
use litebox_common_optee::envelope::{
    LDELF_IMAGE, OPEN_SESSION_META_PARAMS, TA_IMAGE, parse_open_session_meta, rmem_buffer,
};
use litebox_common_optee::{
    OpteeMsgArgs, OpteeMsgArgsHeader, OpteeMsgAttrType, OpteeMsgParamValue, OpteeSmcReturnCode,
    TeeIdentity, TeeOrigin, TeeParamType, TeeResult, TeeUuid, UteeEntryFunc, UteeParamOwned,
    UteeParams,
};
use litebox_common_vm_abi::envelope::{Envelope, Protocol};
use litebox_common_vm_abi::{
    BrokerOp, BrokerOpSet, CallId, CallSet, Image, Message, ProtSet, StartupInfo, UserRange,
};
use litebox_platform_vm_userland::{VmUserland, kcall};
use litebox_shim_optee::session::{OpenSessionTarget, SessionManager, SessionToken, TaInstance};
use litebox_shim_optee::{LoadedProgram, OpteeShim, TaMemrefAddresses, UserConstPtr};
use zerocopy::{FromBytes as _, IntoBytes as _};

type Platform = VmUserland;

const NUM_PARAMS: usize = UteeParamOwned::TEE_NUM_PARAMS;

/// A request from the kernel. Outputs go to `args` and the message window as
/// the TA produces them.
struct Request {
    func: UteeEntryFunc,
    session: u32,
    cmd_id: u32,
    /// `OpenSession` only.
    client: Option<TeeIdentity>,
    params: [UteeParamOwned; NUM_PARAMS],
    /// Client parameters start here in `args`.
    first_param: usize,
    /// Output memrefs' buffers in the message window, by client parameter.
    buffers: [Option<Range<usize>>; NUM_PARAMS],
    message_len: usize,
    payload: Range<usize>,
    args: RefCell<OpteeMsgArgs>,
}

/// `result` may be TA-defined, so it is not a [`TeeResult`].
struct Reply {
    result: u32,
    origin: TeeOrigin,
    session: u32,
}

/// # Safety
///
/// `image` must stay mapped, and unwritten, for the process's lifetime.
unsafe fn image_bytes(image: Image) -> &'static [u8] {
    assert!(
        image.len <= image.region.len,
        "image length exceeds its region"
    );
    let start: usize = image.region.start.trunc();
    // Safety: forwarded to the caller.
    unsafe { core::slice::from_raw_parts(start as *const u8, image.len.trunc()) }
}

/// [`StartupInfo::message_window`]. The kernel writes it only while the
/// runner waits in [`kcall::reply_and_wait`], so borrows of it end with each
/// request.
struct MessageWindow(UserRange);

impl MessageWindow {
    /// # Safety
    ///
    /// `region` must be mapped for the process's lifetime, and accessed only
    /// through the returned value.
    unsafe fn new(region: UserRange) -> Self {
        Self(region)
    }

    fn bytes(&self) -> &[u8] {
        let start: usize = self.0.start.trunc();
        // Safety: see `new`; `&self` excludes `bytes_mut`.
        unsafe { core::slice::from_raw_parts(start as *const u8, self.0.len.trunc()) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        let start: usize = self.0.start.trunc();
        // Safety: see `new`; `&mut self` makes this the only borrow.
        unsafe { core::slice::from_raw_parts_mut(start as *mut u8, self.0.len.trunc()) }
    }
}

struct Runner {
    shim: OpteeShim<Platform>,
    session_manager: &'static SessionManager<Platform>,
    ldelf: &'static [u8],
    ta_uuid: TeeUuid,
    window: MessageWindow,
    /// One instance per process: the kernel starts a process for each. Set
    /// before loading, as a failed first open also ends the instance.
    loaded: bool,
    locked_down: bool,
}

/// Besides [`CallId::Exit`], which is always allowed. Executable memory is
/// not, and asking for it kills the process: nothing may need it once the TA
/// runs (no runtime `dlopen`, ldelf re-entry, or executable `mprotect`).
const SERVING_CALLS: CallSet = CallSet::EMPTY
    .with(CallId::ReplyAndWait)
    .with(CallId::Map)
    .with(CallId::Unmap)
    .with(CallId::Protect)
    .with(CallId::BrokerCall)
    .with(CallId::DeriveKey)
    .with(CallId::Log);

/// All the OP-TEE shim uses.
const SERVING_BROKER_OPS: BrokerOpSet = BrokerOpSet::EMPTY.with(BrokerOp::FillRandom);

/// The session manager tells instances apart by page-table ID; with one
/// instance per process, any constant works.
const INSTANCE_ID: usize = 1;

pub fn serve(info: &StartupInfo) -> ! {
    let platform: &'static Platform = Box::leak(Box::new(VmUserland::new(info)));
    let session_manager: &'static SessionManager<Platform> =
        Box::leak(Box::new(SessionManager::new()));
    let local = litebox_platform_vm_userland::broker::connect(info.broker_shared_memory)
        .unwrap_or_else(|e| panic!("broker association: {e:?}"));
    kcall::restrict(
        CallSet::ALL.without(CallId::BrokerHandshake),
        SERVING_BROKER_OPS,
        ProtSet::ALL,
    )
    .unwrap_or_else(|status| panic!("lockdown: {status:?}"));
    let litebox = litebox::LiteBox::new_with_broker_local(platform, local);
    let shim =
        litebox_shim_optee::OpteeShimBuilder::new_with_litebox(platform, session_manager, litebox)
            .build();

    // Safety: mapped read-only for the process's lifetime; nothing writes
    // them.
    let image = |image: Image| unsafe { image_bytes(image) };
    let (ta, ldelf) = (
        image(info.images[TA_IMAGE]),
        image(info.images[LDELF_IMAGE]),
    );
    let ta_uuid =
        TeeUuid::read_from_bytes(&info.identity[..size_of::<TeeUuid>()]).expect("16-byte UUID");
    assert!(
        shim.store_ta_bin(&ta_uuid, ta),
        "the TA image does not match the process's TA UUID"
    );
    let mut runner = Runner {
        shim,
        session_manager,
        ldelf,
        ta_uuid,
        // Safety: mapped for the process's lifetime; only `Runner` uses it.
        window: unsafe { MessageWindow::new(info.message_window) },
        loaded: false,
        locked_down: false,
    };

    let mut request = kcall::ready(VmUserland::upcall_entry_address())
        .unwrap_or_else(|status| panic!("ready: {status:?}"));
    if cfg!(debug_assertions) {
        // Requires upcalls, registered by `ready`.
        check_guest_memory_access();
        check_lockdown_validation();
    }
    loop {
        let reply = runner.serve(request);
        request =
            kcall::reply_and_wait(&reply).unwrap_or_else(|status| panic!("reply: {status:?}"));
    }
}

fn error_reply(result: TeeResult, origin: TeeOrigin, session: u32) -> Reply {
    Reply {
        result: result.into(),
        origin,
        session,
    }
}

/// Single-threaded, the runner only sees exhaustion and unknown sessions.
fn session_error(error: OpteeSmcReturnCode, session: u32) -> Reply {
    let result = match error {
        OpteeSmcReturnCode::ENomem => TeeResult::OutOfMemory,
        // An unknown session, as in OP-TEE OS.
        OpteeSmcReturnCode::EBadCmd => TeeResult::BadParameters,
        _ => TeeResult::Busy,
    };
    error_reply(result, TeeOrigin::Tee, session)
}

impl Runner {
    /// Replies in place: the same envelope, with the payload and output
    /// buffers updated.
    fn serve(&mut self, message: Message) -> Message {
        let mut request = self.receive(message);
        let reply = match self.decode_params(&mut request) {
            Ok(()) => self.handle(&request),
            Err(result) => error_reply(result, TeeOrigin::Tee, request.session),
        };
        self.send(&request, &reply);
        message
    }

    /// The kernel builds the framing and the arguments' structure, so a
    /// malformed request is the kernel's bug.
    fn receive(&self, message: Message) -> Request {
        let message_len = usize::try_from(message.len)
            .ok()
            .filter(|len| *len <= self.window.bytes().len())
            .expect("a message within the window");
        let envelope =
            Envelope::parse(&self.window.bytes()[..message_len]).expect("a well-formed envelope");
        assert_eq!(
            envelope.protocol(),
            Protocol::OPTEE_MSG,
            "an OP-TEE message"
        );
        let (header, raw) =
            OpteeMsgArgsHeader::read_from_prefix(envelope.payload()).expect("an optee_msg_arg");
        let args = OpteeMsgArgs::from_header_and_raw_params(&header, raw)
            .ok()
            .filter(|args| args.validate().is_ok())
            .expect("a valid optee_msg_arg");
        Request {
            func: UteeEntryFunc::try_from(args.cmd).expect("an entry command"),
            session: args.session,
            cmd_id: args.func,
            client: None,
            params: [const { UteeParamOwned::None }; NUM_PARAMS],
            first_param: 0,
            buffers: [const { None }; NUM_PARAMS],
            message_len,
            payload: envelope.payload_part().range(),
            args: RefCell::new(args),
        }
    }

    /// As `litebox_shim_optee::msg_handler::decode_ta_request`, with memrefs
    /// in the envelope's buffers.
    fn decode_params(&self, request: &mut Request) -> Result<(), TeeResult> {
        let bad = TeeResult::BadParameters;
        let args = *request.args.borrow();
        if request.func == UteeEntryFunc::OpenSession {
            let (ta, client) = parse_open_session_meta(&args).ok_or(bad)?;
            if ta != self.ta_uuid {
                return Err(TeeResult::ItemNotFound);
            }
            request.client = Some(client);
            request.first_param = OPEN_SESSION_META_PARAMS;
        }
        let num_params = usize::try_from(args.num_params).map_err(|_| bad)?;
        if num_params
            .checked_sub(request.first_param)
            .is_none_or(|count| count > NUM_PARAMS)
        {
            return Err(bad);
        }
        let window = self.window.bytes();
        let envelope = Envelope::parse(&window[..request.message_len]).expect("checked on receipt");
        let params = &args.params[request.first_param..num_params];
        for (i, param) in params.iter().enumerate() {
            if param.is_meta() {
                return Err(bad);
            }
            let buffer = || rmem_buffer(&envelope, &param.get_param_rmem()?);
            let value = || param.get_param_value().ok_or(bad);
            request.params[i] = match param.attr_type() {
                OpteeMsgAttrType::None => UteeParamOwned::None,
                OpteeMsgAttrType::ValueInput => UteeParamOwned::ValueInput {
                    value_a: value()?.a,
                    value_b: value()?.b,
                },
                OpteeMsgAttrType::ValueOutput => UteeParamOwned::ValueOutput,
                OpteeMsgAttrType::ValueInout => UteeParamOwned::ValueInout {
                    value_a: value()?.a,
                    value_b: value()?.b,
                },
                OpteeMsgAttrType::RmemInput => UteeParamOwned::MemrefInput {
                    data: Some(window[buffer().ok_or(bad)?].into()),
                },
                OpteeMsgAttrType::RmemOutput => {
                    let range = buffer().ok_or(bad)?;
                    request.buffers[i] = Some(range.clone());
                    UteeParamOwned::MemrefOutput {
                        buffer_size: range.len(),
                    }
                }
                OpteeMsgAttrType::RmemInout => {
                    let range = buffer().ok_or(bad)?;
                    request.buffers[i] = Some(range.clone());
                    UteeParamOwned::MemrefInout {
                        data: Some(window[range.clone()].into()),
                        buffer_size: range.len(),
                    }
                }
                // Temporary memory is physical, which a runner cannot reach.
                _ => return Err(bad),
            };
        }
        Ok(())
    }

    fn send(&mut self, request: &Request, reply: &Reply) {
        let args = *request.args.borrow();
        let mut header = OpteeMsgArgsHeader::from(args);
        header.ret = reply.result;
        header.ret_origin = *reply.origin.value();
        header.session = reply.session;
        let payload = &mut self.window.bytes_mut()[request.payload.clone()];
        args.serialize(payload)
            .expect("the request's payload holds its arguments");
        payload[..size_of::<OpteeMsgArgsHeader>()].copy_from_slice(header.as_bytes());
    }

    fn handle(&mut self, request: &Request) -> Reply {
        let params = &request.params;
        match request.func {
            UteeEntryFunc::OpenSession => self.open_session(request, params),
            UteeEntryFunc::InvokeCommand => self.invoke_command(request, params),
            UteeEntryFunc::CloseSession => self.close_session(request, params),
            UteeEntryFunc::Unknown => {
                error_reply(TeeResult::BadParameters, TeeOrigin::Tee, request.session)
            }
        }
    }

    /// A failed open names no session, as in OP-TEE OS.
    fn open_session(&mut self, request: &Request, params: &[UteeParamOwned; NUM_PARAMS]) -> Reply {
        let mut reply = self.open_session_inner(request, params);
        if reply.result != u32::from(TeeResult::Success) {
            reply.session = 0;
        }
        reply
    }

    fn open_session_inner(
        &mut self,
        request: &Request,
        params: &[UteeParamOwned; NUM_PARAMS],
    ) -> Reply {
        let session_manager = self.session_manager;
        let mut reply = None;
        let ta_uuid = self.ta_uuid;
        let result = session_manager.with_ta(&ta_uuid, |target| {
            reply = Some(match target {
                OpenSessionTarget::NewInstance => self.open_session_new_instance(request, params),
                OpenSessionTarget::Sibling(instance) => {
                    self.open_session_sibling(request, params, instance)
                }
                OpenSessionTarget::Busy => error_reply(TeeResult::Busy, TeeOrigin::Tee, 0),
            });
            Ok(())
        });
        match (result, reply) {
            (Ok(()), Some(reply)) => reply,
            (Err(error), _) => session_error(error, 0),
            (Ok(()), None) => unreachable!("`with_ta` runs its closure on success"),
        }
    }

    /// Dropping the token undisarmed recycles the ID and forgets the
    /// identity.
    fn new_session_token(
        &self,
        request: &Request,
    ) -> Result<SessionToken<'static, Platform>, OpteeSmcReturnCode> {
        let token = self.session_manager.try_acquire_open_session_token()?;
        let session = token.session_id().expect("open-session tokens carry an id");
        self.session_manager
            .set_session_client_identity(session, request.client);
        Ok(token)
    }

    fn open_session_new_instance(
        &mut self,
        request: &Request,
        params: &[UteeParamOwned; NUM_PARAMS],
    ) -> Reply {
        if self.loaded {
            return error_reply(TeeResult::Busy, TeeOrigin::Tee, 0);
        }
        self.loaded = true;
        let (mut token, program) = match self.load_instance(request) {
            Ok(loaded) => loaded,
            Err(reply) => {
                // No TA will run: lock down now.
                self.lock_down();
                return reply;
            }
        };
        let session = token.session_id().expect("open-session tokens carry an id");
        let reply = self.enter(
            &program,
            request,
            params,
            session,
            UteeEntryFunc::OpenSession,
        );
        if reply.result == u32::from(TeeResult::Success) {
            self.session_manager.register_new_session(
                session,
                self.shim.clone(),
                program,
                INSTANCE_ID,
                self.ta_uuid,
            );
            token.disarm();
        }
        reply
    }

    fn load_instance(
        &mut self,
        request: &Request,
    ) -> Result<
        (
            SessionToken<'static, Platform>,
            Box<LoadedProgram<Platform>>,
        ),
        Reply,
    > {
        let token = self
            .new_session_token(request)
            .map_err(|error| session_error(error, 0))?;
        let program = self
            .load()
            .map_err(|result| error_reply(result, TeeOrigin::Tee, 0))?;
        Ok((token, program))
    }

    fn open_session_sibling(
        &mut self,
        request: &Request,
        params: &[UteeParamOwned; NUM_PARAMS],
        instance: &TaInstance<Platform>,
    ) -> Reply {
        let mut token = match self.new_session_token(request) {
            Ok(token) => token,
            Err(error) => return session_error(error, 0),
        };
        let session = token.session_id().expect("open-session tokens carry an id");
        let reply = self.enter(
            instance.loaded_program(),
            request,
            params,
            session,
            UteeEntryFunc::OpenSession,
        );
        if reply.result == u32::from(TeeResult::TargetDead) {
            self.retire_dead_instance(instance);
        } else if reply.result == u32::from(TeeResult::Success) {
            if let Err(error) = self
                .session_manager
                .register_sibling_session(session, instance)
            {
                return session_error(error, 0);
            }
            token.disarm();
        }
        reply
    }

    fn invoke_command(
        &mut self,
        request: &Request,
        params: &[UteeParamOwned; NUM_PARAMS],
    ) -> Reply {
        let session = request.session;
        let session_manager = self.session_manager;
        let mut reply = None;
        let result = session_manager.with_session(session, |instance| {
            let Some(instance) = instance else {
                session_manager.unregister_session(session);
                reply = Some(error_reply(TeeResult::TargetDead, TeeOrigin::Tee, session));
                return Ok(());
            };
            let r = self.enter(
                instance.loaded_program(),
                request,
                params,
                session,
                UteeEntryFunc::InvokeCommand,
            );
            if r.result == u32::from(TeeResult::TargetDead) {
                self.retire_dead_instance(instance);
                session_manager.unregister_session(session);
            }
            reply = Some(r);
            Ok(())
        });
        match (result, reply) {
            (Ok(()), Some(reply)) => reply,
            (Err(error), _) => session_error(error, session),
            (Ok(()), None) => unreachable!("`with_session` runs its closure on success"),
        }
    }

    fn close_session(&mut self, request: &Request, params: &[UteeParamOwned; NUM_PARAMS]) -> Reply {
        let session = request.session;
        let session_manager = self.session_manager;
        let mut reply = None;
        let result = session_manager.with_session(session, |instance| {
            let Some(instance) = instance else {
                session_manager.unregister_session(session);
                reply = Some(error_reply(TeeResult::Success, TeeOrigin::Tee, session));
                return Ok(());
            };
            let r = self.enter(
                instance.loaded_program(),
                request,
                params,
                session,
                UteeEntryFunc::CloseSession,
            );
            if r.result == u32::from(TeeResult::TargetDead) {
                self.retire_dead_instance(instance);
            }
            let flags = session_manager.unregister_session(session);
            litebox_util_log::debug!(
                session:% = session,
                registered:% = flags.is_some();
                "session closed"
            );
            if r.result != u32::from(TeeResult::TargetDead)
                && session_manager.count_sessions_for_instance(instance) == 0
            {
                let keep_alive =
                    flags.is_some_and(|flags| flags.is_single_instance() && flags.is_keep_alive());
                if !keep_alive {
                    session_manager.evict_cached_instance(instance);
                }
            }
            // Closing always succeeds (GlobalPlatform).
            reply = Some(error_reply(
                TeeResult::Success,
                TeeOrigin::TrustedApp,
                session,
            ));
            Ok(())
        });
        match (result, reply) {
            (Ok(()), Some(reply)) => reply,
            (Err(error), _) => session_error(error, session),
            (Ok(()), None) => unreachable!("`with_session` runs its closure on success"),
        }
    }

    /// Per OP-TEE, a panic kills every session of a single-instance TA.
    fn retire_dead_instance(&self, instance: &TaInstance<Platform>) {
        if instance.loaded_program().ta_flags.is_single_instance() {
            self.session_manager
                .mark_sessions_dead_for_instance(instance);
        }
    }

    /// The final lockdown stage (see the module docs); idempotent.
    fn lock_down(&mut self) {
        if !self.locked_down {
            kcall::restrict(SERVING_CALLS, SERVING_BROKER_OPS, ProtSet::NO_EXEC)
                .unwrap_or_else(|status| panic!("lockdown: {status:?}"));
            self.locked_down = true;
        }
    }

    /// Boxed before it runs: the program must not move afterwards.
    fn load(&mut self) -> Result<Box<LoadedProgram<Platform>>, TeeResult> {
        let program = Box::new(
            self.shim
                .load_ldelf(self.ldelf, self.ta_uuid)
                .map_err(|e| {
                    litebox_util_log::error!(error:? = e; "failed to load ldelf");
                    TeeResult::GenericError
                })?,
        );
        let mut ctx = PtRegs::default();
        // Safety: no other guest thread runs.
        unsafe {
            litebox_platform_vm_userland::thread::run_thread_ref(
                program
                    .entrypoints
                    .as_ref()
                    .expect("entrypoints after load"),
                &mut ctx,
            );
        }
        if ctx.rax != 0 {
            litebox_util_log::error!(result:% = format_args!("{:#x}", ctx.rax); "ldelf failed");
            return Err(TeeResult::GenericError);
        }
        Ok(program)
    }

    fn enter(
        &mut self,
        program: &LoadedProgram<Platform>,
        request: &Request,
        params: &[UteeParamOwned; NUM_PARAMS],
        session: u32,
        func: UteeEntryFunc,
    ) -> Reply {
        let entrypoints = program
            .entrypoints
            .as_ref()
            .expect("entrypoints after load");
        let context = entrypoints.load_ta_context_with_shm(
            params,
            &[],
            session,
            func as u32,
            Some(request.cmd_id),
        );
        // The first context load maps the last code: the syscall trampoline.
        self.lock_down();
        let memrefs = match context {
            Ok(memrefs) => memrefs,
            Err(e) => {
                litebox_util_log::error!(error:? = e; "failed to load the TA context");
                return error_reply(TeeResult::GenericError, TeeOrigin::Tee, session);
            }
        };
        let mut ctx = PtRegs::default();
        // Safety: no other guest thread runs.
        unsafe { litebox_platform_vm_userland::thread::reenter_thread_ref(entrypoints, &mut ctx) };
        let result: u32 = ctx.rax.trunc();
        let origin = if result == u32::from(TeeResult::TargetDead) {
            TeeOrigin::Tee
        } else {
            TeeOrigin::TrustedApp
        };
        let mut reply = error_reply(TeeResult::Success, origin, session);
        reply.result = result;
        if let Some(params_address) = program.params_address
            && result != u32::from(TeeResult::TargetDead)
        {
            let utee =
                UserConstPtr::<Platform, UteeParams>::from_usize(params_address).read_at_offset(0);
            if let Some(utee) = utee {
                self.outputs(request, &utee, &memrefs);
            }
        }
        reply
    }

    /// As `litebox_shim_optee::msg_handler::update_optee_msg_args`: values
    /// and sizes for the parameters sent as outputs, and memref data, which a
    /// short buffer does not get.
    /// Memref data comes from the buffers the shim allocated (`memrefs`), not
    /// from where the TA's parameters point.
    fn outputs(&mut self, request: &Request, utee: &UteeParams, memrefs: &TaMemrefAddresses) {
        let mut args = request.args.borrow_mut();
        for (index, sent) in request.params.iter().enumerate() {
            let wire = request.first_param + index;
            let (Ok(kind), Ok(Some((a, b)))) = (utee.get_type(index), utee.get_values(index))
            else {
                continue;
            };
            match (sent, kind) {
                (
                    UteeParamOwned::ValueOutput | UteeParamOwned::ValueInout { .. },
                    TeeParamType::ValueOutput | TeeParamType::ValueInout,
                ) => {
                    let _ = args.set_param_value(wire, OpteeMsgParamValue { a, b, c: 0 });
                }
                (
                    UteeParamOwned::MemrefOutput { .. } | UteeParamOwned::MemrefInout { .. },
                    TeeParamType::MemrefOutput | TeeParamType::MemrefInout,
                ) => {
                    let (Some(range), Some(address)) =
                        (request.buffers[index].clone(), memrefs[index])
                    else {
                        continue;
                    };
                    let _ = args.set_param_memref_size(wire, b);
                    let len: usize = b.trunc();
                    if len > range.len() {
                        continue;
                    }
                    // TA memory; the platform confines the copy to guest memory.
                    match UserConstPtr::<Platform, u8>::from_usize(address).to_owned_slice(len) {
                        Some(data) => self.window.bytes_mut()[range][..len].copy_from_slice(&data),
                        None => {
                            let _ = args.set_param_memref_size(wire, 0);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Self-check (debug builds): faulting guest accesses fail gracefully
/// (upcalls and fixups), and the kernel populates lazy pages.
fn check_guest_memory_access() {
    use litebox::platform::RawMutPointer as _;
    use litebox_common_vm_abi::{PAGE_SIZE, Placement, Populate, Prot, RUNNER_MANAGED_MIN};
    use litebox_shim_optee::UserConstPtr;
    type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

    let addr = usize::try_from(RUNNER_MANAGED_MIN).unwrap();
    let len = usize::try_from(PAGE_SIZE).unwrap();
    let read = || UserConstPtr::<Platform, u64>::from_usize(addr).read_at_offset(0);
    let write = |v| MutPtr::<u64>::from_usize(addr).write_at_offset(0, v);
    assert_eq!(read(), None, "read from unmapped guest memory");
    kcall::map(addr, len, Prot::None, Placement::NoReplace, Populate::Lazy).unwrap();
    assert_eq!(read(), None, "read from inaccessible guest memory");
    kcall::protect(addr, len, Prot::Read).unwrap();
    assert_eq!(write(1), None, "write to read-only guest memory");
    assert_eq!(read(), Some(0), "read from a lazily populated page");
    kcall::protect(addr, len, Prot::ReadWrite).unwrap();
    assert_eq!(write(0x5a), Some(()));
    assert_eq!(read(), Some(0x5a));
    kcall::unmap(addr, len).unwrap();
    assert_eq!(read(), None, "read from unmapped guest memory");
}

/// Self-check (debug builds): unknown lockdown bits are rejected.
fn check_lockdown_validation() {
    use litebox_common_vm_abi::{RestrictRequest, Status};
    let raw = |calls: u64, broker_ops: u64, prots: u32| {
        RestrictRequest::new(
            CallSet::read_from_bytes(calls.as_bytes()).unwrap(),
            BrokerOpSet::read_from_bytes(broker_ops.as_bytes()).unwrap(),
            ProtSet::read_from_bytes(prots.as_bytes()).unwrap(),
        )
    };
    let (calls, ops, prots) = (
        CallSet::ALL.bits(),
        BrokerOpSet::ALL.bits(),
        ProtSet::ALL.bits(),
    );
    for request in [
        raw(calls | 1, ops, prots),
        raw(calls, ops + 1, prots),
        raw(calls, ops, prots + 1),
    ] {
        assert_eq!(kcall::call(&request), Err(Status::InvalidArgument));
    }
}

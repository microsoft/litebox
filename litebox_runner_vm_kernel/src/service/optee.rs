// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OP-TEE TAs in runner processes. From the payload: `runner.elf`,
//! `ldelf.elf`, and `ta.elf` (rewritten or not).
//!
//! One TA instance at a time, in its own process: a new process once the
//! instance ends. That is when its first open fails, when the TA panics, or
//! when its last session closes (unless the TA is single-instance and
//! keep-alive); the runner serves exactly one instance. Only the TA header is
//! checked, not its signature, so a TA can claim any UUID and its derived
//! keys.

use super::Service;
use crate::payload::Payload;
use litebox_broker_core::BrokerCore;
use litebox_common_optee::envelope::{LDELF_IMAGE, TA_IMAGE};
use litebox_common_optee::{TeeOrigin, TeeResult, TeeUuid};
use litebox_common_vm_abi::IDENTITY_LEN;
use litebox_platform_vm_kernel::VmKernel;
use litebox_shim_vm_kernel::optee::{self, Completion, EntryFunc, Invocation};
use litebox_shim_vm_kernel::{Process, ProcessConfig};
use zerocopy::IntoBytes as _;

pub struct Request {
    /// The `OpenSession` target.
    pub ta: TeeUuid,
    pub invocation: Invocation,
}

pub struct Optee {
    platform: &'static VmKernel,
    broker_core: BrokerCore,
    runner: &'static [u8],
    images: [&'static [u8]; 2],
    uuid: TeeUuid,
    tsc_khz: u64,
    keep_alive: bool,
    instance: Option<Instance>,
}

struct Instance {
    process: Process,
    sessions: usize,
    /// Whether an open has succeeded.
    opened: bool,
}

impl Optee {
    /// # Panics
    ///
    /// On a missing or malformed payload file.
    pub fn new(platform: &'static VmKernel, tsc_khz: u64, payload: &Payload) -> Self {
        let file = |name| {
            payload
                .file(name)
                .unwrap_or_else(|| panic!("payload has no {name}"))
        };
        let ta = file("ta.elf");
        let head = litebox_common_optee::parse_ta_head(ta).expect("malformed TA header");
        let mut images = [&[][..]; 2];
        images[LDELF_IMAGE] = file("ldelf.elf");
        images[TA_IMAGE] = ta;
        Self {
            platform,
            broker_core: crate::broker::core(),
            runner: file("runner.elf"),
            images,
            uuid: head.uuid,
            tsc_khz,
            keep_alive: head.flags.is_single_instance() && head.flags.is_keep_alive(),
            instance: None,
        }
    }

    fn spawn(&self) -> Option<Process> {
        let mut identity = [0u8; IDENTITY_LEN];
        identity[..size_of::<TeeUuid>()].copy_from_slice(self.uuid.as_bytes());
        let config = ProcessConfig {
            runner: self.runner,
            images: &self.images,
            identity,
            tsc_khz: self.tsc_khz,
        };
        let mut process = Process::spawn(self.platform, self.broker_core.clone(), &config)
            .inspect_err(|e| litebox_util_log::warn!(error:% = e; "spawn"))
            .ok()?;
        process
            .start()
            .inspect_err(|dead| litebox_util_log::warn!(dead:? = dead; "the runner died starting"))
            .ok()?;
        Some(process)
    }
}

fn tee_error(result: TeeResult) -> Completion {
    Completion {
        result: result.into(),
        origin: *TeeOrigin::Tee.value(),
        session: 0,
        params: Default::default(),
    }
}

impl Service for Optee {
    type Request = Request;
    type Reply = Completion;

    fn call(&mut self, request: Request) -> Completion {
        let func = request.invocation.func;
        if func == EntryFunc::OpenSession {
            if request.ta != self.uuid {
                return tee_error(TeeResult::ItemNotFound);
            }
            if self.instance.is_none() {
                let Some(process) = self.spawn() else {
                    return tee_error(TeeResult::GenericError);
                };
                self.instance = Some(Instance {
                    process,
                    sessions: 0,
                    opened: false,
                });
            }
        }
        // Without an instance, every session is unknown.
        let Some(instance) = self.instance.as_mut() else {
            return tee_error(TeeResult::BadParameters);
        };
        let completion = match optee::call(&mut instance.process, request.invocation) {
            Ok(completion) => completion,
            Err(dead) => {
                litebox_util_log::warn!(dead:? = dead; "the TA instance died");
                self.instance = None;
                return tee_error(TeeResult::TargetDead);
            }
        };
        if completion.result == u32::from(TeeResult::TargetDead) {
            self.instance = None;
            return completion;
        }
        if completion.result == u32::from(TeeResult::Success) {
            match func {
                EntryFunc::OpenSession => {
                    instance.sessions += 1;
                    instance.opened = true;
                }
                EntryFunc::CloseSession => instance.sessions = instance.sessions.saturating_sub(1),
                EntryFunc::InvokeCommand => {}
            }
        }
        if instance.sessions == 0 && !(self.keep_alive && instance.opened) {
            self.instance = None;
        }
        completion
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OP-TEE TAs in runner processes, one per TA instance, under [`TaManager`].
//! From the payload: `runner.elf`, `ldelf.elf`, and TAs as `tas/<name>.elf`
//! (rewritten or not). Only TA headers are checked, not signatures, so a TA
//! can claim any UUID and its derived keys.

use super::Service;
use crate::payload::Payload;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use litebox_common_optee::TeeUuid;
use litebox_common_optee::envelope::{LDELF_IMAGE, TA_IMAGE};
use litebox_common_vm_abi::IDENTITY_LEN;
use litebox_platform_vm_kernel::VmKernel;
use litebox_shim_vm_kernel::optee::Completion;
use litebox_shim_vm_kernel::optee::Invocation;
use litebox_shim_vm_kernel::optee::ta_manager::{InstancePolicy, TaManager};
use litebox_shim_vm_kernel::{Process, ProcessConfig};
use zerocopy::IntoBytes as _;

pub struct Request {
    /// The `OpenSession` target.
    pub ta: TeeUuid,
    pub invocation: Invocation,
}

type Spawn = Box<dyn FnMut(&TeeUuid) -> Result<Process, ()>>;

pub struct Optee {
    manager: TaManager<Process, Spawn>,
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
        let (runner, ldelf) = (file("runner.elf"), file("ldelf.elf"));
        let mut tas = BTreeMap::new();
        let mut policies = alloc::vec::Vec::new();
        for (name, image) in payload.files_under("tas/") {
            let Some(name) = name.strip_suffix(".elf") else {
                continue;
            };
            // Only the header is checked; signatures are not verified.
            let head = litebox_common_optee::parse_ta_head(image)
                .unwrap_or_else(|| panic!("malformed TA header: {name}"));
            let uuid = head.uuid;
            let policy = InstancePolicy {
                single_instance: head.flags.is_single_instance(),
                multi_session: head.flags.is_multi_session(),
                keep_alive: head.flags.is_keep_alive(),
            };
            litebox_util_log::info!(name:% = name, policy:? = policy; "TA");
            assert!(
                tas.insert(uuid, image).is_none(),
                "two TAs with UUID {uuid:?}"
            );
            policies.push((uuid, policy));
        }
        assert!(!tas.is_empty(), "payload has no tas/<name>.elf");
        let broker = litebox_broker_vm_kernel::Broker::new();
        let spawn: Spawn = Box::new(move |uuid: &TeeUuid| {
            let Some(ta) = tas.get(uuid) else {
                litebox_util_log::error!(uuid:? = uuid; "no such TA");
                return Err(());
            };
            let mut images = [&[][..]; 2];
            images[LDELF_IMAGE] = ldelf;
            images[TA_IMAGE] = ta;
            let mut identity = [0u8; IDENTITY_LEN];
            identity[..size_of::<TeeUuid>()].copy_from_slice(uuid.as_bytes());
            let mut process = Process::spawn(
                platform,
                &broker,
                &ProcessConfig {
                    runner,
                    images: &images,
                    identity,
                    tsc_khz,
                },
            )
            .map_err(|error| {
                litebox_util_log::error!(error:? = error; "failed to spawn a TA instance");
            })?;
            process.start().map_err(|dead| {
                litebox_util_log::error!(dead:? = dead; "TA instance died starting");
            })?;
            Ok(process)
        });
        let mut manager = TaManager::new(spawn);
        for (uuid, policy) in policies {
            manager.register(uuid, policy);
        }
        Self { manager }
    }

    /// Live TA instances, for tests.
    pub fn instance_count(&self) -> usize {
        self.manager.instance_count()
    }
}

impl Service for Optee {
    type Request = Request;
    type Reply = Completion;

    fn call(&mut self, request: Request) -> Completion {
        self.manager.call(&request.ta, request.invocation)
    }
}

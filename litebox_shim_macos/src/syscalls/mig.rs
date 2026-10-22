// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! MIG server for the guest's kernel objects (task, thread, host).
//!
//! No routine is served yet: every request gets a `MIG_BAD_ID` reply, like
//! `ipc_kobject_server` for a `msgh_id` without a `mig_hash` entry.

use super::mach_ipc::{KernelObject, Message, error_reply};
use crate::{ShimPlatform, Task};
use alloc::vec::Vec;
use litebox_common_macos::{
    TaskParams,
    mach::{NDR_RECORD, mig},
};

pub(crate) const MACH_NOTIFY_SEND_ONCE: i32 = 0o107;

/// A message body that starts with the NDR record.
pub(crate) fn ndr_body(fields: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(NDR_RECORD.len() + fields.len());
    body.extend_from_slice(&NDR_RECORD);
    body.extend_from_slice(fields);
    body
}

/// The task's `audit_token_t`: auid, euid, egid, ruid, rgid, pid, asid,
/// pidversion. The guest is the only member of audit session 0.
pub(crate) fn audit_token(params: &TaskParams) -> [u32; 8] {
    [
        params.uid,
        params.euid,
        params.egid,
        params.uid,
        params.gid,
        params.pid.cast_unsigned(),
        0,
        1,
    ]
}

impl<P: ShimPlatform> Task<P> {
    /// Every routine served here replies.
    pub(crate) fn serve_mig(&self, object: KernelObject, request: Message) -> Message {
        self.log_unsupported_once(
            "MIG routine",
            request.id.into(),
            format_args!("msgh_id {} to {object:?}", request.id),
        );
        self.global.ipc.lock().destroy_message(request);
        error_reply(mig::BAD_ID)
    }
}

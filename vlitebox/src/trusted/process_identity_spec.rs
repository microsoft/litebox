// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Original ProcessId conversions preserve the creator's u32 value exactly.
//! No allocation validity, uniqueness, namespace membership, lifetime or
//! authority guarantee is inferred. Only the native PID Clone is additionally
//! checked; equality and other derived operations remain unverified.

pub use litebox_broker_protocol::process_identity_spec::{
    process_id_clone_policy, process_identity_policy,
};
pub use litebox_broker_protocol::{ProcessGroupId, ProcessId, SessionId};
